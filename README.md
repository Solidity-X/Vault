# Vault
A "secure" way to lock tokens

This contract allows user to lock their tokens into a vault.
A user can create as many vaults as he likes.
There are no fees for depositing/withdrawing.
Before creating a new Vault please note this:
- Passwords/OTP's need to be provided in form of hash, this hash will be publicly stored so only use secure OTP's (random passwords with no meaning)
- Passwords/OTP's will be made public AFTER the withdraw has accured so don't use any personal information
- A password generator is provided within the code, however given enough information a third party could recreate this, use with caution
Before withdrawing from a Vault please note this:
- Vaults must be withdrawn completly, no partial withdrawls available.
- Anyone can withdraw from a Vault once the locking time is over, provided he has access to all necessary information.
- To Withdraw from a Vault, the depositor needs to sign a message "I, {depositor} confirm that I have signed this message to be able to withdraw the funds from vault id: {vaultId}"
- The signature together with the password must be provided at the withdrawl.
- The requirement of a signature renders bruteforce/cracking the password useless as a hacker must acquire the signature too.

You are free to use the contract, however it would be appreciated if you keep the mention at the beginning of the contract.
While the contract has been tested, it can still be outdated or flawed. Use at your own risk and DYOR.
