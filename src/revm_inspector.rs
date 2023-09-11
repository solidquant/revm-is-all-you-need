use foundry_evm::debug::Instruction;
use log::info;
use revm::{
    interpreter::{InstructionResult, Interpreter},
    Database, EVMData, Inspector,
};

pub struct BaseInspector;

impl<DB: Database> Inspector<DB> for BaseInspector {
    fn step(
        &mut self,
        interpreter: &mut Interpreter,
        _data: &mut EVMData<'_, DB>,
        _is_static: bool,
    ) -> InstructionResult {
        let pc = interpreter.program_counter();
        let op = interpreter.contract.bytecode.bytecode()[pc];
        // info!("[OPCODE] {:?}", op);
        InstructionResult::Continue
    }
}
