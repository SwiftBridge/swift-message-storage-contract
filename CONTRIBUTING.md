# Contributing to Swift Message Storage Contract

Thank you for your interest in contributing to the Swift Message Storage Contract project! We welcome contributions from the community to help improve the project.

## Getting Started

1.  **Fork the repository**: Click the "Fork" button on the top right corner of the repository page.
2.  **Clone your fork**: Clone the repository to your local machine:
    ```bash
    git clone https://github.com/your-username/swift-message-storage-contract.git
    cd swift-message-storage-contract
    ```
3.  **Install dependencies**:
    ```bash
    npm install
    ```

## Development Workflow

1.  **Create a branch**: Create a new branch for your feature or bug fix:
    ```bash
    git checkout -b feature/your-feature-name
    ```
2.  **Make changes**: Implement your changes and ensure they are well-documented.
3.  **Run tests**: Run the test suite to ensure your changes didn't break anything:
    ```bash
    npx hardhat test
    ```
4.  **Lint your code**: Ensure your code follows the project's coding standards:
    ```bash
    npx hardhat check
    ```

## Pull Request Process

1.  **Push your changes**: Push your branch to your forked repository:
    ```bash
    git push origin feature/your-feature-name
    ```
2.  **Open a Pull Request**: Go to the original repository and open a Pull Request (PR) from your fork.
3.  **Describe your changes**: Provide a clear description of your changes and why they are necessary.
4.  **Code Review**: Wait for a maintainer to review your PR. Address any feedback provided.

## coding Standards

*   We use Solidity version `^0.8.19`.
*   Follow the OpenZeppelin coding guidelines where possible.
*   Ensure all new functions have NatSpec documentation.

## Reporting Issues

If you find a bug or have a feature request, please open an issue in the issue tracker. Provide as much detail as possible to help us understand and resolve the issue.

Thank you for contributing!
