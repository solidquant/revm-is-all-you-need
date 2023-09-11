use anyhow::{anyhow, Result};
use ethers::{
    abi::{self, parse_abi},
    core::utils::keccak256,
    prelude::*,
    providers::{call_raw::RawCall, Provider, Ws},
    types::{spoof, Block, BlockNumber, TransactionRequest, H160, H256},
};
use log::info;
use revm::{
    db::{EthersDB, InMemoryDB},
    primitives::Bytecode,
    primitives::{keccak256 as rkeccak256, AccountInfo, TransactTo, TxEnv, B160, U256 as rU256},
    Database, EVM,
};
use std::{str::FromStr, sync::Arc, time::Instant};

use crate::constants::{Env, SIMULATOR_CODE};
use crate::foundry_examples::foundry_v2_simulate_swap;
use crate::revm_examples::{
    create_evm_instance, evm_env_setup, get_tx_result, revm_contract_deploy_and_tracing,
};
use crate::tokens::get_implementation;

pub static TEN_ETH: Lazy<U256> = Lazy::new(|| {
    U256::from(10)
        .checked_mul(U256::from(10).pow(U256::from(18)))
        .unwrap()
});

pub static AMOUNT_IN: Lazy<U256> = Lazy::new(|| {
    U256::from(1)
        .checked_mul(U256::from(10).pow(U256::from(18)))
        .unwrap()
});

// 200 GWEI
pub static GAS_PRICE: Lazy<U256> = Lazy::new(|| {
    U256::from(200)
        .checked_mul(U256::from(10).pow(U256::from(9)))
        .unwrap()
});

pub static SIMULATOR_ADDRESS: Lazy<H160> =
    Lazy::new(|| H160::from_str("0xF2d01Ee818509a9540d8324a5bA52329af27D19E").unwrap());

pub async fn eth_call_simulation(
    provider: Arc<Provider<Ws>>,
    block: Block<H256>,
    account: H160,
    target_pair: H160,
    input_token: H160,
    output_token: H160,
    input_balance_slot: i32,
) -> Result<(U256, U256)> {
    let input_token_balance_slot = keccak256(&abi::encode(&[
        abi::Token::Address(*SIMULATOR_ADDRESS),
        abi::Token::Uint(U256::from(input_balance_slot)),
    ]));

    let mut state = spoof::state();
    state.account(account).balance(*TEN_ETH).nonce(0.into());
    state
        .account(*SIMULATOR_ADDRESS)
        .code((*SIMULATOR_CODE).clone());
    state.account(input_token).store(
        input_token_balance_slot.into(),
        H256::from_low_u64_be((*TEN_ETH).as_u64()),
    );

    let simulator_abi = BaseContract::from(
        parse_abi(&[
            "function v2SimulateSwap(uint256,address,address,address) external returns (uint256, uint256)",
        ]).unwrap()
    );
    let calldata = simulator_abi
        .encode(
            "v2SimulateSwap",
            ((*AMOUNT_IN), target_pair, input_token, output_token),
        )
        .unwrap();
    let tx = TransactionRequest::default()
        .from(account)
        .to(*SIMULATOR_ADDRESS)
        .value(U256::zero())
        .data(calldata.0)
        .nonce(U256::zero())
        .gas(5000000)
        .gas_price(*GAS_PRICE)
        .chain_id(1)
        .into();
    let result = provider
        .call_raw(&tx)
        .state(&state)
        .block(block.number.unwrap().into())
        .await
        .unwrap();
    let out: (U256, U256) = simulator_abi
        .decode_output("v2SimulateSwap", result)
        .unwrap();
    Ok(out)
}

pub async fn revm_simulation<M: Middleware + 'static>(
    evm: &mut EVM<InMemoryDB>,
    provider: Arc<M>,
    block: Block<H256>,
    account: H160,
    factory: H160,
    target_pair: H160,
    input_token: H160,
    output_token: H160,
    input_balance_slot: i32,
    output_balance_slot: i32,
    input_token_implementation: Option<H160>,
    output_token_implementation: Option<H160>,
) -> Result<(U256, U256)> {
    let mut ethersdb = EthersDB::new(provider.clone(), Some(block.number.unwrap().into())).unwrap();

    let db = evm.db.as_mut().unwrap();

    let user_acc_info = AccountInfo::new((*TEN_ETH).into(), 0, Bytecode::default());
    db.insert_account_info(account.into(), user_acc_info);

    let simulator_acc_info = AccountInfo::new(
        rU256::ZERO,
        0,
        Bytecode::new_raw((*SIMULATOR_CODE.0).into()),
    );
    db.insert_account_info((*SIMULATOR_ADDRESS).into(), simulator_acc_info);

    let input_token_address = match input_token_implementation {
        Some(implementation) => implementation,
        None => input_token,
    };
    let output_token_address = match output_token_implementation {
        Some(implementation) => implementation,
        None => output_token,
    };
    let input_token_acc_info = ethersdb.basic(input_token_address.into()).unwrap().unwrap();
    let output_token_acc_info = ethersdb
        .basic(output_token_address.into())
        .unwrap()
        .unwrap();
    let factory_acc_info = ethersdb.basic(factory.into()).unwrap().unwrap();

    db.insert_account_info(input_token.into(), input_token_acc_info);
    db.insert_account_info(output_token.into(), output_token_acc_info);
    db.insert_account_info(factory.into(), factory_acc_info);

    let factory_abi = BaseContract::from(
        parse_abi(&["function createPair(address,address) external returns (address)"]).unwrap(),
    );
    let calldata = factory_abi
        .encode("createPair", (input_token, output_token))
        .unwrap();
    let create_pair_tx = TxEnv {
        caller: account.into(),
        gas_limit: 5000000,
        gas_price: (*GAS_PRICE).into(),
        gas_priority_fee: None,
        transact_to: TransactTo::Call(factory.into()),
        value: rU256::ZERO,
        data: calldata.0,
        chain_id: None,
        nonce: None,
        access_list: Default::default(),
    };
    evm.env.tx = create_pair_tx;

    let result = match evm.transact_commit() {
        Ok(result) => result,
        Err(e) => return Err(anyhow!("EVM call failed: {:?}", e)),
    };
    let result = get_tx_result(result).unwrap();

    let pair_created_log = &result.logs.unwrap()[0];
    let token0: B160 = pair_created_log.topics[1].into();
    let token1: B160 = pair_created_log.topics[2].into();

    let db = evm.db.as_mut().unwrap();

    let reserves_slot = rU256::from(8);
    let original_reserves = ethersdb.storage(target_pair.into(), reserves_slot).unwrap();
    db.insert_account_storage(target_pair.into(), reserves_slot, original_reserves)
        .unwrap();

    let pair_abi = BaseContract::from(
        parse_abi(&["function getReserves() external view returns (uint112,uint112,uint32)"])
            .unwrap(),
    );
    let calldata = pair_abi.encode("getReserves", ()).unwrap();
    evm.env.tx.transact_to = TransactTo::Call(target_pair.into());
    evm.env.tx.data = calldata.0;
    let result = match evm.transact_ref() {
        Ok(result) => result,
        Err(e) => return Err(anyhow!("EVM call failed: {:?}", e)),
    };
    let result = get_tx_result(result.result)?;
    let reserves: (U256, U256, U256) = pair_abi
        .decode_output("getReserves", result.output)
        .unwrap();

    let db = evm.db.as_mut().unwrap();

    let (balance_slot_0, balance_slot_1) = if token0 == input_token.into() {
        (input_balance_slot, output_balance_slot)
    } else {
        (output_balance_slot, input_balance_slot)
    };

    let pair_token0_slot = rkeccak256(&abi::encode(&[
        abi::Token::Address(target_pair.into()),
        abi::Token::Uint(U256::from(balance_slot_0)),
    ]));
    db.insert_account_storage(token0, pair_token0_slot.into(), reserves.0.into())?;

    let pair_token1_slot = rkeccak256(&abi::encode(&[
        abi::Token::Address(target_pair.into()),
        abi::Token::Uint(U256::from(balance_slot_1)),
    ]));
    db.insert_account_storage(token1, pair_token1_slot.into(), reserves.1.into())?;

    let slot_in = rkeccak256(&abi::encode(&[
        abi::Token::Address((*SIMULATOR_ADDRESS).into()),
        abi::Token::Uint(U256::from(input_balance_slot)),
    ]));
    db.insert_account_storage(input_token.into(), slot_in.into(), (*TEN_ETH).into())
        .unwrap();

    let simulator_abi = BaseContract::from(
            parse_abi(&[
                "function v2SimulateSwap(uint256,address,address,address) external returns (uint256, uint256)",
            ])?
        );
    let calldata = simulator_abi.encode(
        "v2SimulateSwap",
        (*AMOUNT_IN, target_pair, input_token, output_token),
    )?;
    let v2_simulate_swap_tx = TxEnv {
        caller: account.into(),
        gas_limit: 5000000,
        gas_price: (*GAS_PRICE).into(),
        gas_priority_fee: None,
        transact_to: TransactTo::Call((*SIMULATOR_ADDRESS).into()),
        value: rU256::ZERO,
        data: calldata.0,
        chain_id: None,
        nonce: None,
        access_list: Default::default(),
    };
    evm.env.tx = v2_simulate_swap_tx;

    let result = match evm.transact_commit() {
        Ok(result) => result,
        Err(e) => return Err(anyhow!("EVM call failed: {:?}", e)),
    };
    let result = get_tx_result(result)?;
    let out: (U256, U256) = simulator_abi.decode_output("v2SimulateSwap", result.output)?;

    Ok(out)
}

pub async fn benchmark_function() {
    dotenv::dotenv().ok();

    let user = H160::from_str("0xE2b5A9c1e325511a227EF527af38c3A7B65AFA1d").unwrap();

    let weth = H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
    let usdt = H160::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();

    let weth_usdt_pair = H160::from_str("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").unwrap();
    let uniswap_v2_factory = H160::from_str("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f").unwrap();

    let env = Env::new();
    let ws = Ws::connect(&env.wss_url).await.unwrap();
    let provider = Arc::new(Provider::new(ws));

    let block = provider
        .get_block(BlockNumber::Latest)
        .await
        .unwrap()
        .unwrap();

    let mut evm = create_evm_instance();
    evm_env_setup(&mut evm);

    let weth_balance_slot =
        revm_contract_deploy_and_tracing(&mut evm, provider.clone(), weth, user)
            .await
            .unwrap();
    let usdt_balance_slot =
        revm_contract_deploy_and_tracing(&mut evm, provider.clone(), usdt, user)
            .await
            .unwrap();

    let weth_implementation = get_implementation(provider.clone(), weth, block.number.unwrap())
        .await
        .unwrap();
    let usdt_implementation = get_implementation(provider.clone(), usdt, block.number.unwrap())
        .await
        .unwrap();

    let runs = 10;

    // eth_call simulation
    {
        let mut tooks = Vec::new();

        for _ in 0..runs {
            let s = Instant::now();
            let out = eth_call_simulation(
                provider.clone(),
                block.clone(),
                user,
                weth_usdt_pair,
                weth,
                usdt,
                weth_balance_slot,
            )
            .await
            .unwrap();
            let took = s.elapsed().as_micros();
            tooks.push(took as i32);
            info!(
                "[eth_call] Result: {:?} / Took: {:?} microseconds",
                out, took
            );
        }

        let avg_took = tooks.clone().into_iter().sum::<i32>() / (tooks.len() as i32);
        info!("[eth_call] Average took: {:?} microseconds", avg_took);
    }

    // revm simulation
    {
        let mut tooks = Vec::new();

        for _ in 0..runs {
            let mut evm = create_evm_instance();
            evm_env_setup(&mut evm);

            let s = Instant::now();
            let out = revm_simulation(
                &mut evm,
                provider.clone(),
                block.clone(),
                user,
                uniswap_v2_factory,
                weth_usdt_pair,
                weth,
                usdt,
                weth_balance_slot,
                usdt_balance_slot,
                weth_implementation,
                usdt_implementation,
            )
            .await
            .unwrap();
            let took = s.elapsed().as_micros();
            tooks.push(took as i32);
            info!("[revm] Result: {:?} / Took: {:?} microseconds", out, took);
        }

        let avg_took = tooks.clone().into_iter().sum::<i32>() / (tooks.len() as i32);
        info!("[revm] Average took: {:?} microseconds", avg_took);
    }

    // foundry simulation
    {
        let mut tooks = Vec::new();

        for _ in 0..runs {
            let s = Instant::now();
            let out = foundry_v2_simulate_swap(
                provider.clone(),
                user,
                weth_usdt_pair,
                weth,
                usdt,
                weth_balance_slot,
            )
            .await
            .unwrap();
            let took = s.elapsed().as_micros();
            tooks.push(took as i32);
            info!(
                "[foundry] Result: {:?} / Took: {:?} microseconds",
                out, took
            );
        }

        let avg_took = tooks.clone().into_iter().sum::<i32>() / (tooks.len() as i32);
        info!("[revm] Average took: {:?} microseconds", avg_took);
    }
}
