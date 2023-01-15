use alloc::collections::BTreeMap;

use crate::{fb::CONSOLE, println};

mod acpi;
mod pci;

lazy_static::lazy_static! {
    static ref COMMANDS: BTreeMap<&'static str, CommandInfo> = {
        let mut map = BTreeMap::new();

        map.insert("help", CommandBuilder::new().description("print this help message").exec(help_fn));
        map.insert("clear", CommandBuilder::new().description("clear the console").exec(clear_fn));

        map.insert("lsacpi", CommandBuilder::new().description("print AML table traversal").exec(acpi::acpi_fn));
        map.insert("acpisearch", CommandBuilder::new().description("search ACPI hierarchy").exec(acpi::acpi_search_fn));

        map.insert("lspci", CommandBuilder::new().description("list attached PCI devices").exec(pci::lspci_fn));

        map
    };
}

pub fn clear_fn(_: &str) {
    CONSOLE.lock().clear();
}

pub fn help_fn(command: &str) {
    println!("os_temple command console");
    for (k, v) in COMMANDS.iter() {
        crate::println!("{}\t{}", k, v.description.unwrap_or("no description"))
    }
}

struct CommandInfo {
    pub(self) description: Option<&'static str>,
    pub(self) implementation: fn(&str) -> (),
}

struct CommandBuilder {
    description: Option<&'static str>,
}

impl CommandBuilder {
    fn new() -> Self {
        Self { description: None }
    }

    pub fn description(&mut self, description: &'static str) -> &mut Self {
        self.description = Some(description);
        self
    }

    pub fn exec(&mut self, implementation: fn(&str) -> ()) -> CommandInfo {
        CommandInfo {
            description: self.description,
            implementation,
        }
    }
}

pub async fn run_command(command: &str) {
    let base_command = command.split_once(" ").map(|(v, _)| v).unwrap_or(command);
    if let Some(cmd) = COMMANDS.get(base_command) {
        (cmd.implementation)(command);
    } else {
        crate::println!("No such command: {}", command);
    }
}
