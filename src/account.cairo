#[starknet::contract]
mod Account {
    use realmaccount::components::AccountComponent;
    use openzeppelin::introspection::src5::SRC5Component;
    use starknet::ContractAddress;

    component!(path: AccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    // Account
    #[abi(embed_v0)]
    impl SRC6Impl = AccountComponent::SRC6Impl<ContractState>;
    #[abi(embed_v0)]
    impl SRC6CamelOnlyImpl = AccountComponent::SRC6CamelOnlyImpl<ContractState>;
    #[abi(embed_v0)]
    impl DeclarerImpl = AccountComponent::DeclarerImpl<ContractState>;
    #[abi(embed_v0)]
    impl DeployableImpl = AccountComponent::DeployableImpl<ContractState>;
    #[abi(embed_v0)]
    impl AccountTokenImpl = AccountComponent::AccountTokenImpl<ContractState>;
    #[abi(embed_v0)]
    impl AccountCallImpl = AccountComponent::AccountCallImpl<ContractState>;

    
    impl AccountInternalImpl = AccountComponent::InternalImpl<ContractState>;

    // SRC5
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: AccountComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: AccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event
    }

    #[constructor]
    fn constructor(ref self: ContractState, token_address: ContractAddress, token_id: u256) {
        self.account.initializer(:token_address, :token_id)
    }
}