#[starknet::interface]
trait IERC721Mint<TContractState> {
    fn mint(ref self: TContractState, to: starknet::ContractAddress, token_id: u256);
}

#[starknet::contract]
mod ERC721 {
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc721::ERC721Component;
    use starknet::ContractAddress;

    component!(path: ERC721Component, storage: erc721, event: ERC721Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    // ERC721
    #[abi(embed_v0)]
    impl ERC721Impl = ERC721Component::ERC721Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC721MetadataImpl = ERC721Component::ERC721MetadataImpl<ContractState>;
    #[abi(embed_v0)]
    impl ERC721CamelOnly = ERC721Component::ERC721CamelOnlyImpl<ContractState>;
    #[abi(embed_v0)]
    impl ERC721MetadataCamelOnly =
        ERC721Component::ERC721MetadataCamelOnlyImpl<ContractState>;
    impl ERC721InternalImpl = ERC721Component::InternalImpl<ContractState>;

    // SRC5
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc721: ERC721Component::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC721Event: ERC721Component::Event,
        #[flat]
        SRC5Event: SRC5Component::Event
    }

    mod Errors {
        const UNEQUAL_ARRAYS: felt252 = 'Array lengths do not match';
    }

    /// Sets the token `name` and `symbol`.
    /// Mints the `token_ids` tokens to `recipient` and sets
    /// each token's URI.
    #[constructor]
    fn constructor(
        ref self: ContractState,
        name: felt252,
        symbol: felt252
    ) {
        self.erc721.initializer(name, symbol);
    }

    #[abi(embed_v0)]
    impl ERC721Mint of super::IERC721Mint<ContractState> {
        fn mint(ref self: ContractState, to: ContractAddress, token_id: u256) {
            self.erc721._mint(to, token_id);
        }
    }

}