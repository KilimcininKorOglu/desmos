fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let code = desmos_cli::Dispatcher::with_standard_commands().dispatch(argv);
    std::process::exit(code);
}
