// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract AssetManagementPlatform is ReentrancyGuard {
    address public owner;
    
    // Структура для хранения баланса токена
    struct TokenBalance {
        address tokenAddress;
        uint256 balance;
        uint256 initialInvestment;
    }
    
    // Структура для транзакции
    struct Transaction {
        address user;
        address token;
        uint256 amount;
        bool isDeposit;
        uint256 timestamp;
    }
    
    // Структура для пользователя
    struct User {
        string username;
        string passwordHash; // Хеш пароля
        bool isRegistered;
        uint256 registrationDate;
        uint256 lastLogin;
    }
    
    // Маппинги для хранения данных
    mapping(address => mapping(address => uint256)) public userTokenBalances;
    mapping(address => mapping(address => uint256)) public userInitialInvestments;
    mapping(address => address[]) public userTokens;
    mapping(uint256 => Transaction) public transactions;
    mapping(address => User) public users;
    mapping(string => bool) public usernameTaken;
    mapping(address => bool) public isUserActive; // Сессии пользователей
    
    // Переменные управления
    uint256 public transactionCount;
    address[] public supportedTokens;
    mapping(address => bool) public isTokenSupported;
    
    // События
    event Deposit(address indexed user, address indexed token, uint256 amount, uint256 timestamp);
    event Withdraw(address indexed user, address indexed token, uint256 amount, uint256 timestamp);
    event TokenSupported(address indexed token, bool supported);
    event UserRegistered(address indexed user, string username, uint256 timestamp);
    event UserLoggedIn(address indexed user, uint256 timestamp);
    event UserLoggedOut(address indexed user, uint256 timestamp);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier onlyRegisteredUser() {
        require(users[msg.sender].isRegistered, "User not registered");
        _;
    }
    
    modifier onlyActiveUser() {
        require(isUserActive[msg.sender], "User not logged in");
        _;
    }

    // === РЕГИСТРАЦИЯ И АВТОРИЗАЦИЯ ===
    
    // Функция для создания хеша пароля
    function hashPassword(string memory _password) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_password));
    }
    
    function register(string memory _username, string memory _password) external {
        require(!users[msg.sender].isRegistered, "User already registered");
        require(bytes(_username).length >= 3, "Username must be at least 3 characters");
        require(bytes(_password).length >= 6, "Password must be at least 6 characters");
        require(!usernameTaken[_username], "Username already taken");
        require(bytes(_username).length <= 32, "Username too long");
        
        bytes32 passwordHash = hashPassword(_password);
        
        users[msg.sender] = User({
            username: _username,
            passwordHash: string(abi.encodePacked(passwordHash)),
            isRegistered: true,
            registrationDate: block.timestamp,
            lastLogin: 0
        });
        
        usernameTaken[_username] = true;
        
        emit UserRegistered(msg.sender, _username, block.timestamp);
    }
    
    // Авторизация с логином и паролем
    function login(string memory _password) external onlyRegisteredUser returns (bool) {
        User storage user = users[msg.sender];
        bytes32 inputPasswordHash = hashPassword(_password);
        bytes32 storedPasswordHash = bytes32(bytes(user.passwordHash));
        
        require(inputPasswordHash == storedPasswordHash, "Invalid password");
        
        isUserActive[msg.sender] = true;
        user.lastLogin = block.timestamp;
        
        emit UserLoggedIn(msg.sender, block.timestamp);
        return true;
    }
    
    function logout() external {
        require(isUserActive[msg.sender], "User not logged in");
        isUserActive[msg.sender] = false;
        emit UserLoggedOut(msg.sender, block.timestamp);
    }
    
    function getUserInfo(address _user) external view returns (User memory) {
        return users[_user];
    }
    
    function isLoggedIn(address _user) external view returns (bool) {
        return isUserActive[_user];
    }

    // === УПРАВЛЕНИЕ ТОКЕНАМИ ===
    
    function addSupportedToken(address _token) external onlyOwner {
        require(!isTokenSupported[_token], "Token already supported");
        require(_token != address(0), "Invalid token address");
        
        supportedTokens.push(_token);
        isTokenSupported[_token] = true;
        
        emit TokenSupported(_token, true);
    }
    
    function removeSupportedToken(address _token) external onlyOwner {
        require(isTokenSupported[_token], "Token not supported");
        
        isTokenSupported[_token] = false;
        
        for (uint i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == _token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }
        
        emit TokenSupported(_token, false);
    }

    // === ДИАГНОСТИЧЕСКИЕ ФУНКЦИИ ===
    
    function checkAllowance(address _token) external view returns (uint256) {
        IERC20 token = IERC20(_token);
        return token.allowance(msg.sender, address(this));
    }
    
    function checkTokenBalance(address _token) external view returns (uint256) {
        IERC20 token = IERC20(_token);
        return token.balanceOf(msg.sender);
    }
    
    function checkContractTokenBalance(address _token) external view returns (uint256) {
        IERC20 token = IERC20(_token);
        return token.balanceOf(address(this));
    }

    // === ОСНОВНЫЕ ФУНКЦИИ ===
    
    function deposit(address _token, uint256 _amount) external nonReentrant onlyRegisteredUser onlyActiveUser {
        require(isTokenSupported[_token], "Token not supported");
        require(_amount > 0, "Amount must be greater than 0");
        
        IERC20 token = IERC20(_token);
        
        // Проверяем allowance
        uint256 currentAllowance = token.allowance(msg.sender, address(this));
        require(currentAllowance >= _amount, string(abi.encodePacked("Insufficient allowance. Current: ", uint2str(currentAllowance), ", Required: ", uint2str(_amount))));
        
        // Проверяем баланс пользователя
        uint256 userBalance = token.balanceOf(msg.sender);
        require(userBalance >= _amount, string(abi.encodePacked("Insufficient token balance. Current: ", uint2str(userBalance), ", Required: ", uint2str(_amount))));
        
        // Переводим токены
        require(token.transferFrom(msg.sender, address(this), _amount), "Transfer failed");
        
        // Обновляем балансы
        if (userTokenBalances[msg.sender][_token] == 0) {
            userTokens[msg.sender].push(_token);
        }
        
        userTokenBalances[msg.sender][_token] += _amount;
        userInitialInvestments[msg.sender][_token] += _amount;
        
        // Записываем транзакцию
        transactions[transactionCount] = Transaction({
            user: msg.sender,
            token: _token,
            amount: _amount,
            isDeposit: true,
            timestamp: block.timestamp
        });
        transactionCount++;
        
        emit Deposit(msg.sender, _token, _amount, block.timestamp);
    }
    
    function withdraw(address _token, uint256 _amount) external nonReentrant onlyRegisteredUser onlyActiveUser {
        require(userTokenBalances[msg.sender][_token] >= _amount, "Insufficient balance");
        require(_amount > 0, "Amount must be greater than 0");
        
        IERC20 token = IERC20(_token);
        
        // Обновляем балансы
        userTokenBalances[msg.sender][_token] -= _amount;
        
        // Переводим токены пользователю
        require(token.transfer(msg.sender, _amount), "Transfer failed");
        
        // Записываем транзакцию
        transactions[transactionCount] = Transaction({
            user: msg.sender,
            token: _token,
            amount: _amount,
            isDeposit: false,
            timestamp: block.timestamp
        });
        transactionCount++;
        
        emit Withdraw(msg.sender, _token, _amount, block.timestamp);
    }

    // === ФУНКЦИИ ПОЛУЧЕНИЯ ДАННЫХ ===
    
    function getTokenBalance(address _user, address _token) external view returns (uint256) {
        return userTokenBalances[_user][_token];
    }
    
    function getUserTokens(address _user) external view returns (address[] memory) {
        return userTokens[_user];
    }
    
    function calculateProfitability(address _user, address _token) external view returns (int256) {
        uint256 currentBalance = userTokenBalances[_user][_token];
        uint256 initialInvestment = userInitialInvestments[_user][_token];
        
        if (initialInvestment == 0) return 0;
        
        return int256(currentBalance) - int256(initialInvestment);
    }
    
    function getPortfolioValue(address _user) external view returns (uint256) {
        uint256 totalValue = 0;
        address[] memory tokens = userTokens[_user];
        
        for (uint i = 0; i < tokens.length; i++) {
            totalValue += userTokenBalances[_user][tokens[i]];
        }
        
        return totalValue;
    }
    
    function getUserTransactions(address _user, uint256 _limit) external view returns (Transaction[] memory) {
        uint256 count = 0;
        
        for (uint i = 0; i < transactionCount; i++) {
            if (transactions[i].user == _user) {
                count++;
            }
        }
        
        if (_limit > 0 && count > _limit) {
            count = _limit;
        }
        
        Transaction[] memory userTx = new Transaction[](count);
        uint256 index = 0;
        
        for (uint i = transactionCount; i > 0 && index < count; i--) {
            if (transactions[i-1].user == _user) {
                userTx[index] = transactions[i-1];
                index++;
            }
        }
        
        return userTx;
    }
    
    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }
    
    function isUserRegistered(address _user) external view returns (bool) {
        return users[_user].isRegistered;
    }

    // === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===
    
    function uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
}