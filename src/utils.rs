use anyhow::{self, Result};
use ethers::types::U256;
use fern::colors::{Color, ColoredLevelConfig};
use log::LevelFilter;
use rand::Rng;

pub fn setup_logger() -> Result<()> {
    let colors = ColoredLevelConfig {
        trace: Color::Cyan,
        debug: Color::Magenta,
        info: Color::Green,
        warn: Color::Red,
        error: Color::BrightRed,
        ..ColoredLevelConfig::new()
    };

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{}[{}] {}",
                chrono::Local::now().format("[%H:%M:%S]"),
                colors.color(record.level()),
                message
            ))
        })
        .chain(std::io::stdout())
        .level(log::LevelFilter::Error)
        .level_for("revm_is_all_you_need", LevelFilter::Info)
        .apply()?;

    Ok(())
}

pub fn calculate_next_block_base_fee(
    gas_used: U256,
    gas_limit: U256,
    base_fee_per_gas: U256,
) -> U256 {
    let gas_used = gas_used;

    let mut target_gas_used = gas_limit / 2;
    target_gas_used = if target_gas_used == U256::zero() {
        U256::one()
    } else {
        target_gas_used
    };

    let new_base_fee = {
        if gas_used > target_gas_used {
            base_fee_per_gas
                + ((base_fee_per_gas * (gas_used - target_gas_used)) / target_gas_used)
                    / U256::from(8u64)
        } else {
            base_fee_per_gas
                - ((base_fee_per_gas * (target_gas_used - gas_used)) / target_gas_used)
                    / U256::from(8u64)
        }
    };

    let seed = rand::thread_rng().gen_range(0..9);
    new_base_fee + seed
}
