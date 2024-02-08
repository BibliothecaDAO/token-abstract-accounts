use starknet::ContractAddress;
use starknet::ClassHash;

#[starknet::interface]
trait IRegistry<TContractState> {
    fn create_account(
        ref self: TContractState,
        class_hash: ClassHash,
        token_address: ContractAddress,
        token_id: u256,
    ) -> ContractAddress;
    fn account(
        self: @TContractState,
        class_hash: ClassHash,
        token_address: ContractAddress,
        token_id: u256
    ) -> ContractAddress;
    
}



#[starknet::contract]
mod Registry {

    use super::IRegistry;

    use openzeppelin::token::erc721::interface::{IERC721DispatcherTrait, IERC721Dispatcher};

    use starknet::{ContractAddress, SyscallResultTrait, ClassHash, deploy_syscall};

    use core::hash::HashStateTrait;
    use core::pedersen::PedersenTrait;


    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AccountCreated: AccountCreated
    }


    #[derive(Drop, starknet::Event)]
    struct AccountCreated {
        token_address: ContractAddress,
        token_id: u256,
        account_address: ContractAddress
    }


    const STARKNET_CONTRACT_ADDRESS: felt252 = 'STARKNET_CONTRACT_ADDRESS';
    const DEPLOYMENT_SALT: felt252 = 0;

    #[external(v0)]
    impl IRegistryImpl of IRegistry<ContractState> {

        fn create_account(
            ref self: ContractState,
            class_hash: ClassHash,
            token_address: ContractAddress,
            token_id: u256
        ) -> ContractAddress {

            // create constructor calldata
            let mut constructor_calldata: Array<felt252> = array![];
            token_address.serialize(ref constructor_calldata);
            token_id.serialize(ref constructor_calldata);

            // deploy the account contract
            let (account_address, _) 
                = deploy_syscall(
                    class_hash, DEPLOYMENT_SALT, constructor_calldata.span(), true
                    ).unwrap_syscall();

            // note that you can only depend on this event to show
            // that an account was deployed "from this registry"

            self.emit(
                AccountCreated { 
                    token_address, 
                    token_id, 
                    account_address 
                }
            );

            account_address
        }


        fn account(self: @ContractState, class_hash: ClassHash, token_address: ContractAddress, token_id: u256) -> ContractAddress {

            let constructor_calldata_hash = PedersenTrait::new(0)
                .update(token_address.into())
                .update(token_id.low.into())
                .update(token_id.high.into())
                .update(3)
                .finalize();

            let address = PedersenTrait::new(0)
                .update(STARKNET_CONTRACT_ADDRESS)
                .update(0)
                .update(DEPLOYMENT_SALT)
                .update(class_hash.into())
                .update(constructor_calldata_hash)
                .update(5)
                .finalize();

            address.try_into().unwrap()
        }
    }

}