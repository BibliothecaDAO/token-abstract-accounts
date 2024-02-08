// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.8.1 (account/account.cairo)

/// # Account Component
///
/// The Account component enables contracts to behave as accounts.


#[starknet::interface]
trait IAccountToken<TState> {
    fn get_token_id(self: @TState) -> u256;
    fn get_token_address(self: @TState) -> starknet::ContractAddress;
    fn get_token_owner(self: @TState) -> starknet::ContractAddress;
}

#[starknet::component]
mod AccountComponent {

    use openzeppelin::account::interface;
    use openzeppelin::token::erc721::interface::{IERC721Dispatcher, IERC721DispatcherTrait};
    use openzeppelin::account::AccountComponent as OZAccountComponent;
    use openzeppelin::account::interface::{ISRC6Dispatcher, ISRC6DispatcherTrait};
    use openzeppelin::introspection::src5::SRC5Component::InternalTrait as SRC5InternalTrait;
    use openzeppelin::introspection::src5::SRC5Component;
    use starknet::account::Call;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::get_tx_info;

    const MIN_TRANSACTION_VERSION: u256 = 1;
    const QUERY_OFFSET: u256 = 0x100000000000000000000000000000000;

    #[storage]
    struct Storage {
        Account_token_id: u256,
        Account_token_address: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        OwnerAdded: OwnerAdded,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnerAdded {
        token_address: starknet::ContractAddress,
        token_id: u256
    }



    mod Errors {
        const INVALID_CALLER: felt252 = 'Account: invalid caller';
        const INVALID_SIGNATURE: felt252 = 'Account: invalid signature';
        const INVALID_TX_VERSION: felt252 = 'Account: invalid tx version';
    }

    #[embeddable_as(SRC6Impl)]
    impl SRC6<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::ISRC6<ComponentState<TContractState>> {
        /// Executes a list of calls from the account.
        ///
        /// Requirements:
        ///
        /// - The transaction version must be greater than or equal to `MIN_TRANSACTION_VERSION`.
        /// - If the transaction is a simulation (version than `QUERY_OFFSET`), it must be
        /// greater than or equal to `QUERY_OFFSET` + `MIN_TRANSACTION_VERSION`.
        fn __execute__(
            self: @ComponentState<TContractState>, mut calls: Array<Call>
        ) -> Array<Span<felt252>> {
            // Avoid calls from other contracts
            // https://github.com/OpenZeppelin/cairo-contracts/issues/344
            let sender = get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);

            // Check tx version
            let tx_info = get_tx_info().unbox();
            let tx_version: u256 = tx_info.version.into();
            // Check if tx is a query
            if (tx_version >= QUERY_OFFSET) {
                assert(
                    QUERY_OFFSET + MIN_TRANSACTION_VERSION <= tx_version, Errors::INVALID_TX_VERSION
                );
            } else {
                assert(MIN_TRANSACTION_VERSION <= tx_version, Errors::INVALID_TX_VERSION);
            }

            OZAccountComponent::_execute_calls(calls)
        }

        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `invoke` transactions.
        fn __validate__(self: @ComponentState<TContractState>, mut calls: Array<Call>) -> felt252 {
            self.validate_transaction()
        }

        /// Verifies that the given signature is valid for the given hash.
        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            if self._is_valid_signature(hash, signature) {
                starknet::VALIDATED
            } else {
                0
            }
        }
    }


    /// Adds camelCase support for `ISRC6`.
    #[embeddable_as(SRC6CamelOnlyImpl)]
    impl SRC6CamelOnly<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::ISRC6CamelOnly<ComponentState<TContractState>> {
        fn isValidSignature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            self.is_valid_signature(hash, signature)
        }
    }



    #[embeddable_as(DeclarerImpl)]
    impl Declarer<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IDeclarer<ComponentState<TContractState>> {
        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `declare` transactions.
        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252
        ) -> felt252 {
            self.validate_transaction()
        }
    }

    #[embeddable_as(DeployableImpl)]
    impl Deployable<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IDeployable<ComponentState<TContractState>> {
        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `deploy_account` transactions.
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252
        ) -> felt252 {
            self.validate_transaction()
        }
    }



    #[embeddable_as(AccountTokenImpl)]
    impl AccountToken<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of super::IAccountToken<ComponentState<TContractState>> {
        /// Returns the current token id associated with the account
        fn get_token_id(self: @ComponentState<TContractState>) -> u256 {
            self.Account_token_id.read()
        }

        /// Returns the address of the connected nft
        fn get_token_address(self: @ComponentState<TContractState>) -> ContractAddress {
            self.Account_token_address.read()
        }

        /// Returns the current owner of the account
        fn get_token_owner(self: @ComponentState<TContractState>) -> ContractAddress {
            self.account_token_owner()
        }
    }




    #[generate_trait]
    impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        impl SRC5: SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of InternalTrait<TContractState> {
        /// Initializes the account by setting the initial public key
        /// and registering the ISRC6 interface Id.
        fn initializer(ref self: ComponentState<TContractState>, token_address: ContractAddress, token_id: u256) {
            let mut src5_component = get_dep_component_mut!(ref self, SRC5);
            src5_component.register_interface(interface::ISRC6_ID);
            self._set_token_id(token_address, token_id);
        }

        /// Validates the signature for the current transaction.
        /// Returns the short string `VALID` if valid, otherwise it reverts.
        fn validate_transaction(self: @ComponentState<TContractState>) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let mut signature = tx_info.signature;
            let mut signature_arr = array![];
            
            // todo@credence is this necessary?

            // convert signature span to array
            core::array::serialize_array_helper(signature, ref signature_arr);
     

            assert(self._is_valid_signature(tx_hash, signature_arr), Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        fn account_token_owner(self: @ComponentState<TContractState>) -> ContractAddress {
            return IERC721Dispatcher {contract_address: self.Account_token_address.read()}
            .owner_of(self.Account_token_id.read());
        }


        /// Sets the public key without validating the caller.
        /// The usage of this method outside the `set_public_key` function is discouraged.
        ///
        /// Emits an `OwnerAdded` event.
        fn _set_token_id(ref self: ComponentState<TContractState>, token_address: ContractAddress, token_id: u256) {
            self.Account_token_address.write(token_address);
            self.Account_token_id.write(token_id);
            self.emit(OwnerAdded { token_id, token_address });
        }


        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.

        fn _is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> bool {

            let src6 = ISRC6Dispatcher {contract_address: self.account_token_owner()};
            if src6.is_valid_signature(hash, signature) == starknet::VALIDATED {
                return true;
            } 
            return false;
        }
    }
}
