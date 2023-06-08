# Overview

This project aims to provide test implementations for the "rust-pcap" library. 
The "rust-pcap" library offers a high-level interface for capturing traffic and working with packet capture (PCAP) files in Rust.
The primary objective of this test project is to ensure the functionality, reliability, and compatibility of the "rust-pcap" library. By creating comprehensive tests, we can verify that the library functions as expected and can handle various scenarios.

## Getting Started

To get started with this test project, follow the steps below:

1. Clone the "rust_pcap_test" repository to your local machine.
2. Make sure you have Rust installed on your system. If not, you can install it from the official [Rust website](https://www.rust-lang.org/).
3. Navigate to the root directory of the cloned repository.

## Running the Tests

To execute the tests, use the following commands.
A typical run with logs at DEBUG level (INFO is the default):

```bash
RUSTFLAGS=-Awarnings RUST_LOG="debug" cargo run --release
```

The CLI supports flags for device and filter for simpler development.
For example, to capture only traffic to eyalzo.com (that supports clear text http), use this (the -d is optional):
```bash
RUSTFLAGS=-Awarnings RUST_LOG="trace" cargo run -- -f "host 50.87.176.106 and tcp" -d "en0"
```


This command will build and run all the defined tests within the project.

## Contributing

Contributions to enhance the test project for the "rust-pcap" library, "rust_pcap_test," are highly appreciated. 
If you would like to contribute, please follow these guidelines:

1. Fork this repository and clone it to your local machine.
2. Create a new branch for your feature or bug fix.
3. Implement your changes and write tests as necessary.
4. Make sure all existing tests pass and add new tests to cover your changes.
5. Commit your changes and push them to your forked repository.
6. Open a pull request in this repository, explaining your changes and the rationale behind them.

Please adhere to the project's coding style and guidelines.

## License

The "rust_pcap_test" project is licensed under the [MIT License](LICENSE.md). 
Review the license before making contributions to this project.

## Contact

If you have any questions, suggestions, or need assistance, feel free to reach out to the project maintainers or contributors via GitHub. 
You can also open an issue in the "rust_pcap_test" repository.

---

Thank you for your interest in contributing to the "rust_pcap_test" project! 
Your contributions will help improve the reliability and quality of the "rust-pcap" library.
