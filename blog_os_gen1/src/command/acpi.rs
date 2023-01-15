use aml::AmlName;

use crate::acpi_aml::aml_context;

pub fn acpi_fn(command: &str) {
    let mut cx = aml_context().lock();

    let passed_root = command.split_once(" ").map(|(_, r)| r);

    let root_value = passed_root
        .clone()
        .and_then(|arg| match AmlName::from_str(arg) {
            Ok(ref n) => match cx.namespace.get_by_path(n) {
                Ok(v) => Some(v),
                Err(_) => {
                    crate::println!("no such name: {}", n);
                    None
                }
            },
            Err(_) => {
                crate::println!("failed to parse AML name: {}", arg);
                None
            }
        });

    if passed_root.is_some() && root_value.is_none() {
        return;
    }

    if let Some(value) = root_value {
        crate::println!("{:#?}", value);
    } else {
        // Full traversal
        cx.namespace.traverse(|name, level| {
            crate::println!("{}: {:?}", name.clone().normalize().unwrap(), level.typ);

            crate::waste_time();

            Ok(true)
        });
    }
}

pub fn acpi_search_fn(command: &str) {
    let mut cx = aml_context().lock();

    let passed_root = command.split_once(" ").map(|(_, r)| r);

    let found_value = passed_root
        .clone()
        .and_then(|arg| match AmlName::from_str(arg) {
            Ok(ref n) => match cx.namespace.search_for_level(n, &AmlName::root()) {
                Ok(v) => Some(v),
                Err(_) => {
                    crate::println!("no such name: {}", n);
                    None
                }
            },
            Err(_) => {
                crate::println!("failed to parse AML name: {}", arg);
                None
            }
        });

    if let Some(v) = found_value {
        let v = cx.namespace.get_handle(&v);
        crate::println!("Found: {:?}", v);
    } else {
        crate::println!("No value found during search.")
    }
}
