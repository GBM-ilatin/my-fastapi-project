```python
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import bcrypt
from typing import Dict, List, Optional


class User:
    """User model class."""
    def __init__(self, user_id: int, username: str, email: str, password_hash: str, created_at: datetime = None):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.created_at = created_at or datetime.now()
        self.is_active = True


class UserRepository:
    """Mock user repository interface."""
    def find_by_id(self, user_id: int) -> Optional[User]:
        pass
    
    def find_by_username(self, username: str) -> Optional[User]:
        pass
    
    def find_by_email(self, email: str) -> Optional[User]:
        pass
    
    def save(self, user: User) -> User:
        pass
    
    def delete(self, user_id: int) -> bool:
        pass
    
    def find_all(self) -> List[User]:
        pass


class UserManagement:
    """User management component for handling user operations."""
    
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def create_user(self, username: str, email: str, password: str) -> User:
        """Create a new user with hashed password."""
        if self.user_repository.find_by_username(username):
            raise ValueError("Username already exists")
        
        if self.user_repository.find_by_email(email):
            raise ValueError("Email already exists")
        
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user = User(
            user_id=None,
            username=username,
            email=email,
            password_hash=password_hash
        )
        
        return self.user_repository.save(user)
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Retrieve user by ID."""
        if user_id <= 0:
            raise ValueError("User ID must be positive")
        
        return self.user_repository.find_by_id(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Retrieve user by username."""
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")
        
        return self.user_repository.find_by_username(username.strip())
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password."""
        user = self.get_user_by_username(username)
        
        if not user or not user.is_active:
            return None
        
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return user
        
        return None
    
    def update_user(self, user_id: int, **kwargs) -> User:
        """Update user information."""
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if 'username' in kwargs:
            existing_user = self.user_repository.find_by_username(kwargs['username'])
            if existing_user and existing_user.user_id != user_id:
                raise ValueError("Username already exists")
            user.username = kwargs['username']
        
        if 'email' in kwargs:
            existing_user = self.user_repository.find_by_email(kwargs['email'])
            if existing_user and existing_user.user_id != user_id:
                raise ValueError("Email already exists")
            user.email = kwargs['email']
        
        if 'password' in kwargs:
            if len(kwargs['password']) < 8:
                raise ValueError("Password must be at least 8 characters long")
            user.password_hash = bcrypt.hashpw(
                kwargs['password'].encode('utf-8'), 
                bcrypt.gensalt()
            ).decode('utf-8')
        
        return self.user_repository.save(user)
    
    def delete_user(self, user_id: int) -> bool:
        """Delete user by ID."""
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        return self.user_repository.delete(user_id)
    
    def deactivate_user(self, user_id: int) -> User:
        """Deactivate user account."""
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        user.is_active = False
        return self.user_repository.save(user)
    
    def activate_user(self, user_id: int) -> User:
        """Activate user account."""
        user = self.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        user.is_active = True
        return self.user_repository.save(user)
    
    def list_all_users(self) -> List[User]:
        """Get all users."""
        return self.user_repository.find_all()


# Test fixtures
@pytest.fixture
def mock_user_repository():
    """Create a mock user repository."""
    return Mock(spec=UserRepository)


@pytest.fixture
def user_management(mock_user_repository):
    """Create UserManagement instance with mock repository."""
    return UserManagement(mock_user_repository)


@pytest.fixture
def sample_user():
    """Create a sample user for testing."""
    return User(
        user_id=1,
        username="testuser",
        email="test@example.com",
        password_hash="$2b$12$hashed_password",
        created_at=datetime(2023, 1, 1, 12, 0, 0)
    )


@pytest.fixture
def sample_users():
    """Create multiple sample users for testing."""
    return [
        User(1, "user1", "user1@example.com", "$2b$12$hash1"),
        User(2, "user2", "user2@example.com", "$2b$12$hash2"),
        User(3, "user3", "user3@example.com", "$2b$12$hash3")
    ]


class TestUserManagement:
    """Test suite for UserManagement class."""
    
    def test_create_user_success(self, user_management, mock_user_repository):
        """Test successful user creation."""
        # Arrange
        mock_user_repository.find_by_username.return_value = None
        mock_user_repository.find_by_email.return_value = None
        created_user = User(1, "newuser", "new@example.com", "hashed_password")
        mock_user_repository.save.return_value = created_user
        
        # Act
        with patch('bcrypt.hashpw') as mock_hashpw, patch('bcrypt.gensalt') as mock_gensalt:
            mock_gensalt.return_value = b'salt'
            mock_hashpw.return_value = b'hashed_password'
            result = user_management.create_user("newuser", "new@example.com", "password123")
        
        # Assert
        assert result == created_user
        mock_user_repository.find_by_username.assert_called_once_with("newuser")
        mock_user_repository.find_by_email.assert_called_once_with("new@example.com")
        mock_user_repository.save.assert_called_once()
    
    def test_create_user_username_exists(self, user_management, mock_user_repository, sample_user):
        """Test user creation fails when username already exists."""
        # Arrange
        mock_user_repository.find_by_username.return_value = sample_user
        
        # Act & Assert
        with pytest.raises(ValueError, match="Username already exists"):
            user_management.create_user("testuser", "new@example.com", "password123")
    
    def test_create_user_email_exists(self, user_management, mock_user_repository, sample_user):
        """Test user creation fails when email already exists."""
        # Arrange
        mock_user_repository.find_by_username.return_value = None
        mock_user_repository.find_by_email.return_value = sample_user
        
        # Act & Assert
        with pytest.raises(ValueError, match="Email already exists"):
            user_management.create_user("newuser", "test@example.com", "password123")
    
    def test_create_user_password_too_short(self, user_management, mock_user_repository):
        """Test user creation fails with short password."""
        # Arrange
        mock_user_repository.find_by_username.return_value = None
        mock_user_repository.find_by_email.return_value = None
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password must be at least 8 characters long"):
            user_management.create_user("newuser", "new@example.com", "short")
    
    def test_get_user_by_id_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user retrieval by ID."""
        # Arrange
        mock_user_repository.find_by_id.return_value = sample_user
        
        # Act
        result = user_management.get_user_by_id(1)
        
        # Assert
        assert result == sample_user
        mock_user_repository.find_by_id.assert_called_once_with(1)
    
    def test_get_user_by_id_not_found(self, user_management, mock_user_repository):
        """Test user retrieval by ID when user not found."""
        # Arrange
        mock_user_repository.find_by_id.return_value = None
        
        # Act
        result = user_management.get_user_by_id(999)
        
        # Assert
        assert result is None
        mock_user_repository.find_by_id.assert_called_once_with(999)
    
    def test_get_user_by_id_invalid_id(self, user_management):
        """Test user retrieval with invalid ID."""
        # Act & Assert
        with pytest.raises(ValueError, match="User ID must be positive"):
            user_management.get_user_by_id(0)
        
        with pytest.raises(ValueError, match="User ID must be positive"):
            user_management.get_user_by_id(-1)
    
    def test_get_user_by_username_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user retrieval by username."""
        # Arrange
        mock_user_repository.find_by_username.return_value = sample_user
        
        # Act
        result = user_management.get_user_by_username("testuser")
        
        # Assert
        assert result == sample_user
        mock_user_repository.find_by_username.assert_called_once_with("testuser")
    
    def test_get_user_by_username_with_whitespace(self, user_management, mock_user_repository, sample_user):
        """Test user retrieval by username with whitespace."""
        # Arrange
        mock_user_repository.find_by_username.return_value = sample_user
        
        # Act
        result = user_management.get_user_by_username("  testuser  ")
        
        # Assert
        assert result == sample_user
        mock_user_repository.find_by_username.assert_called_once_with("testuser")
    
    def test_get_user_by_username_empty(self, user_management):
        """Test user retrieval with empty username."""
        # Act & Assert
        with pytest.raises(ValueError, match="Username cannot be empty"):
            user_management.get_user_by_username("")
        
        with pytest.raises(ValueError, match="Username cannot be empty"):
            user_management.get_user_by_username("   ")
    
    def test_authenticate_user_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user authentication."""
        # Arrange
        mock_user_repository.find_by_username.return_value = sample_user
        
        # Act
        with patch('bcrypt.checkpw', return_value=True):
            result = user_management.authenticate_user("testuser", "password123")
        
        # Assert
        assert result == sample_user
    
    def test_authenticate_user_wrong_password(self, user_management, mock_user_repository, sample_user):
        """Test authentication with wrong password."""
        # Arrange
        mock_user_repository.find_by_username.return_value = sample_user
        
        # Act
        with patch('bcrypt.checkpw', return_value=False):
            result = user_management.authenticate_user("testuser", "wrongpassword")
        
        # Assert
        assert result is None
    
    def test_authenticate_user_not_found(self, user_management, mock_user_repository):
        """Test authentication when user not found."""
        # Arrange
        mock_user_repository.find_by_username.return_value = None
        
        # Act
        result = user_management.authenticate_user("nonexistent", "password123")
        
        # Assert
        assert result is None
    
    def test_authenticate_user_inactive(self, user_management, mock_user_repository, sample_user):
        """Test authentication with inactive user."""
        # Arrange
        sample_user.is_active = False
        mock_user_repository.find_by_username.return_value = sample_user
        
        # Act
        result = user_management.authenticate_user("testuser", "password123")
        
        # Assert
        assert result is None
    
    def test_update_user_username(self, user_management, mock_user_repository, sample_user):
        """Test updating user username."""
        # Arrange
        mock_user_repository.find_by_id.return_value = sample_user
        mock_user_repository.find_by_username.return_value = None
        updated_user = User(1, "newusername", "test@example.com", "hashed_password")
        mock_user_repository.save.return_value = updated_user
        
        # Act
        result = user_management.update_user(1, username="newusername")
        
        # Assert
        assert result == updated_user
        assert sample_user.username == "newusername"
        mock_user_repository.save.assert_called_once_with(sample_user)
    
    def test_update_user_email(self, user_management, mock_user_repository, sample_user):
        """Test updating user email."""
        # Arrange
        mock_user_repository.find_by_id.return_value = sample_user
        mock_user_repository.find_by_email.return_value = None
        updated_user = User(1, "testuser", "newemail@example.com", "hashed_password")
        mock_user_repository.save.return_value = updated_user
        
        # Act
        result = user_management.update_user(1, email="newemail@example.com")
        
        # Assert
        assert result == updated_user
        assert sample_user.email