// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/*\
Created by SolidityX for Decision Game
Telegram: @solidityX
\*/


import "@openzeppelin/contracts/utils/Strings.sol";

interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function burn(uint256 amount) external; 
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
}

contract Vaults {
    mapping(uint => vault) vaultInfo;
    mapping(address => stats) vaultOfToken;
    mapping(address => uint[]) vaultsOf;
    address owner;
    uint runningCount = 1;
    bytes32[] hashes;

    constructor() {
        owner = msg.sender;
    }

    /*\
    this struct holds the information of each deposit
    The hash is public so only use OTP and not actual passwords.
    \*/
    struct vault {
        address depositor;
        address token;
        uint amount;
        uint lockedFor;
        uint unlock;
        bytes32 hash;
    }

    /*\
    this struct hold information about each address
    \*/
    struct stats {
        uint totalVaults;
        uint amountLocked;
    }
    
    
/*//////////////////////////////////////////////‾‾‾‾‾‾‾‾‾‾\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*\
///////////////////////////////////////////////executeables\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\____________/////////////////////////////////////////////*/


    /*\
    create a new vault
    \*/
    function deposit(address _token, uint _amount, uint _lockFor, bytes32 _hash) public returns(bool, uint) {
        uint BalBef = IERC20(_token).balanceOf(address(this));
        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "transfer failed!");
        require(_token != address(0x0), "token invalid!");
        require(_amount >= 1000000 , "amount invalid!");
        require(_lockFor > 0, "lockFor invalid!");
        require(_hash != bytes32(0x0), "hash invalid!");

        vault memory v = vault(msg.sender, _token, IERC20(_token).balanceOf(address(this))-BalBef, _lockFor, block.timestamp + _lockFor, _hash);
        vaultInfo[runningCount] = v;
        vaultOfToken[_token].totalVaults++;
        vaultOfToken[_token].amountLocked += _amount;
        hashes.push(_hash);
        vaultsOf[msg.sender].push(runningCount);
        runningCount++;
        return (true, runningCount-1);
    }

    /*\
    withdraw from a vault.
    Any address can withdraw the vault as long as the lock time has passed, the password is known and the depositor signed the withdraw.
    \*/
    function withdraw(uint _id, string memory _pass, bytes memory _sig) public returns (bool) {
        require(_verifyMessage(_id, _sig), "please verify withdrawl!");
        require(vaultInfo[_id].token != address(0x0), "invalid id!");
        require(block.timestamp > vaultInfo[_id].unlock, "still locked!");
        require(sha256(abi.encode(_pass)) == vaultInfo[_id].hash, "wrong password!");

        vault memory v = vault(address(0x0), address(0x0), 0, 0, 0, bytes32(0x0));
        uint amount = vaultInfo[_id].amount;
        IERC20 token = IERC20(vaultInfo[_id].token);
        vaultInfo[_id] = v;
        vaultOfToken[address(token)].totalVaults--;
        vaultOfToken[address(token)].amountLocked -= amount;
        require(token.transfer(msg.sender, amount * 99 / 100));
        require(token.transfer(owner, amount / 100));
        return true;
    }


/*//////////////////////////////////////////////‾‾‾‾‾‾‾‾‾‾‾\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*\
///////////////////////////////////////////////viewable/misc\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_____________/////////////////////////////////////////////*/

    /*\
    returns all active vaults of a address
    \*/
    function getActiveVaultIdsOf(address _addr) public view returns(uint[] memory) {
        uint count;
        uint[] memory _ids = new uint[](getTotalVaults(_addr));
        for(uint i; i < _ids.length; i++) {
            if(vaultInfo[vaultsOf[_addr][i]].unlock < block.timestamp) {
                _ids[count] = vaultsOf[_addr][i];
                count++;
            }
        }
        uint[] memory _ACids = new uint[](count);
        for(uint i; i < count; i++) {
            _ACids[i] = _ids[i];
        }
        return _ACids;
    }

    /*\
    get all active vaults from all users
    \*/
    function getAllActiveVaulIds() public view returns(uint[] memory) {
        uint count;
        uint[] memory _ids = new uint[](runningCount-1);
        for(uint i; i < _ids.length; i++) {
            if(vaultInfo[i].unlock < block.timestamp) {
                _ids[count] = i;
                count++;
            }
        }
        uint[] memory _ACids = new uint[](count);
        for(uint i; i < count; i++) {
            _ACids[i] = _ids[i];
        }
        return _ACids;
    }

    /*\
    users can use this to generate a OTP and it hash. However anyone that has enough information could recreate this, only use if in secure envoirment.
    \*/
    function generateOTP(string memory _seed, uint _nonce) public view returns(string memory _pass, bytes32 _hash, bool _used) {
        bytes memory alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$%&/()=?{[]}+-*/-_.:;,'~#@^";
        _pass = Strings.toString(uint(keccak256(abi.encode(address(this).balance, block.timestamp, _seed, _nonce, block.difficulty, blockhash(block.number)))));
        bytes memory _newPass = bytes(_pass);
        for(uint i; i < _newPass.length; i++) {
            _newPass[i] = alphabet[uint(keccak256(abi.encode(address(this).balance, block.timestamp, _seed, _nonce, block.difficulty, blockhash(block.number)))) % alphabet.length];
            _nonce++;
        }
        (bytes32 hash, bool used) = hashPass(_pass);
        _hash = hash;
        _used = used;
    }

    /*\
    users can use this to hash their OPT's, these hashes are used as inputs for vault creation
    \*/
    function hashPass(string memory _OTP) public view returns(bytes32 _hash, bool _used) {
        _hash = sha256(abi.encode(_OTP));
        for(uint i; i < hashes.length; i++) {
            if(hashes[i] == _hash) {
                _used = true;
                break;
            }
        }
    }



    /*\
    returns the number of vaults of a token
    \*/
    function getTotalVaultsOf(address _token) public view returns(uint) {
        return vaultOfToken[_token].totalVaults;
    }

    /*\
    returns the total locked tokens of a token
    \*/
    function getTotalDepositsOf(address _token) public view returns(uint) {
        return vaultOfToken[_token].amountLocked;
    }

    /*\
    returns the the token of a vault
    \*/
    function getTokenOf(uint _vault) public view returns(address) {
        return vaultInfo[_vault].token;
    }

    /*\
    returns the amount that has been locked in a vault
    \*/
    function getDepositOf(uint _vault) public view returns(uint) {
        return vaultInfo[_vault].amount;
    }

    /*\
    returns how long the vault is locked for
    \*/
    function getLockTimeOf(uint _vault) public view returns(uint) {
        return vaultInfo[_vault].lockedFor;
    }

    /*\
    returns the unlocking time of the vault
    \*/
    function getLockedUntilOf(uint _vault) public view returns(uint) {
        return vaultInfo[_vault].unlock;
    }

    /*\
    returns the total amount of vaults a user has
    \*/
    function getTotalVaults(address _of) public view returns(uint) {
        return vaultsOf[_of].length;
    }

    /*\
    returns all the ids of the vaults the user has created
    \*/
    function getVaultIds(address _of) public view returns(uint[] memory) {
        return vaultsOf[_of];
    }



    /*\
    helper function to hash messages
    \*/
    function _getMessageHash(string memory _message) private pure returns(bytes32) {
        return keccak256(abi.encodePacked(_message));
    }

    /*\
    helper function to hash signed messages
    \*/
    function _getEthSignedMessageHash(bytes32 _messageHash) private pure returns(bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    /*\
    helper function to split the signature in its corresponding elements
    \*/
    function _split(bytes memory _sig) private pure returns(bytes32 r, bytes32 s, uint8 v) {
        require(_sig.length == 65, "invalid length!");
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
    }

    /*\
    helper function to validate signature
    \*/
    function _recover(bytes32 _ethSignedMessageHash, bytes memory _sig) private pure returns(address) {
        (bytes32 r, bytes32 s, uint8 v) = _split(_sig);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    /*\
    verifies if the signer of the message is equal to the depositer of the vault
    \*/
    function _verifyMessage(uint _id, bytes memory _sig) private view returns(bool) {
        string memory _message = string(abi.encodePacked("I, ", Strings.toHexString(uint160(vaultInfo[_id].depositor), 20), " confirm that I have signed this message to be able to withdraw the funds from vault id: ", Strings.toString(_id)));
        bytes32 messageHash = _getMessageHash(_message);
        bytes32 ethSignedMessageHash = _getEthSignedMessageHash(messageHash);

        return (vaultInfo[_id].depositor == _recover(ethSignedMessageHash, _sig));
    }

}
