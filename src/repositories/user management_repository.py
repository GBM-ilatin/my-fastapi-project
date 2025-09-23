```python
# src/models/user.py
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field
from pydantic import EmailStr


class UserBase(SQLModel):
    """Base user model with common fields."""
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    is_active: bool = Field(default=True)


class User(UserBase, table=True):
    """User database model."""
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    password_hash: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default=None)


class UserCreate(UserBase):
    """User creation model."""
    password: str = Field(min_length=8)


class UserUpdate(SQLModel):
    """User update model."""
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(default=None, min_length=3, max_length=50)
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8)


class UserRead(UserBase):
    """User read model."""
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
```

```python
# src/repositories/user_repository.py
from abc import ABC, abstractmethod
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from ..models.user import User, UserCreate, UserUpdate
from ..exceptions import UserNotFoundError, UserAlreadyExistsError, DatabaseError


class UserRepositoryInterface(ABC):
    """Abstract interface for user repository."""
    
    @abstractmethod
    async def create(self, user_data: UserCreate) -> User:
        """Create a new user."""
        pass
    
    @abstractmethod
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        pass
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        pass
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        pass
    
    @abstractmethod
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """Get all users with pagination."""
        pass
    
    @abstractmethod
    async def update(self, user_id: int, user_data: UserUpdate) -> User:
        """Update user."""
        pass
    
    @abstractmethod
    async def delete(self, user_id: int) -> bool:
        """Delete user."""
        pass
    
    @abstractmethod
    async def exists_by_email(self, email: str) -> bool:
        """Check if user exists by email."""
        pass
    
    @abstractmethod
    async def exists_by_username(self, username: str) -> bool:
        """Check if user exists by username."""
        pass


class SQLUserRepository(UserRepositoryInterface):
    """SQLAlchemy implementation of user repository."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, user_data: UserCreate) -> User:
        """
        Create a new user.
        
        Args:
            user_data: User creation data
            
        Returns:
            Created user
            
        Raises:
            UserAlreadyExistsError: If user with email or username already exists
            DatabaseError: If database operation fails
        """
        try:
            # Check if user already exists
            if await self.exists_by_email(user_data.email):
                raise UserAlreadyExistsError(f"User with email {user_data.email} already exists")
            
            if await self.exists_by_username(user_data.username):
                raise UserAlreadyExistsError(f"User with username {user_data.username} already exists")
            
            # Create user (password hashing should be handled in service layer)
            user = User(
                email=user_data.email,
                username=user_data.username,
                first_name=user_data.first_name,
                last_name=user_data.last_name,
                is_active=user_data.is_active,
                password_hash=user_data.password  # This should be hashed in service layer
            )
            
            self.session.add(user)
            await self.session.commit()
            await self.session.refresh(user)
            
            return user
            
        except IntegrityError as e:
            await self.session.rollback()
            raise UserAlreadyExistsError("User with provided data already exists") from e
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to create user: {str(e)}") from e
    
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User if found, None otherwise
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            statement = select(User).where(User.id == user_id)
            result = await self.session.execute(statement)
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get user by ID: {str(e)}") from e
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.
        
        Args:
            email: User email
            
        Returns:
            User if found, None otherwise
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            statement = select(User).where(User.email == email)
            result = await self.session.execute(statement)
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get user by email: {str(e)}") from e
    
    async def get_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User if found, None otherwise
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            statement = select(User).where(User.username == username)
            result = await self.session.execute(statement)
            return result.scalar_one_or_none()
        except Exception as e:
            raise DatabaseError(f"Failed to get user by username: {str(e)}") from e
    
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all users with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of users
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            statement = select(User).offset(skip).limit(limit)
            result = await self.session.execute(statement)
            return result.scalars().all()
        except Exception as e:
            raise DatabaseError(f"Failed to get users: {str(e)}") from e
    
    async def update(self, user_id: int, user_data: UserUpdate) -> User:
        """
        Update user.
        
        Args:
            user_id: User ID
            user_data: User update data
            
        Returns:
            Updated user
            
        Raises:
            UserNotFoundError: If user not found
            UserAlreadyExistsError: If email or username already exists
            DatabaseError: If database operation fails
        """
        try:
            # Check if user exists
            user = await self.get_by_id(user_id)
            if not user:
                raise UserNotFoundError(f"User with ID {user_id} not found")
            
            # Prepare update data
            update_data = user_data.dict(exclude_unset=True)
            if not update_data:
                return user
            
            # Check for email/username conflicts
            if "email" in update_data and update_data["email"] != user.email:
                if await self.exists_by_email(update_data["email"]):
                    raise UserAlreadyExistsError(f"User with email {update_data['email']} already exists")
            
            if "username" in update_data and update_data["username"] != user.username:
                if await self.exists_by_username(update_data["username"]):
                    raise UserAlreadyExistsError(f"User with username {update_data['username']} already exists")
            
            # Handle password hashing (should be done in service layer)
            if "password" in update_data:
                update_data["password_hash"] = update_data.pop("password")
            
            update_data["updated_at"] = datetime.utcnow()
            
            # Update user
            statement = (
                update(User)
                .where(User.id == user_id)
                .values(**update_data)
            )
            await self.session.execute(statement)
            await self.session.commit()
            
            # Return updated user
            return await self.get_by_id(user_id)
            
        except (UserNotFoundError, UserAlreadyExistsError):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to update user: {str(e)}") from e
    
    async def delete(self, user_id: int) -> bool:
        """
        Delete user.
        
        Args:
            user_id: User ID
            
        Returns:
            True if user was deleted, False if not found
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            statement = delete(User).where(User.id == user_id)
            result = await self.session.execute(statement)
            await self.session.commit()
            
            return result.rowcount > 0
            
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to delete user: {str(e)}") from e
    
    async def exists_by_email(self, email: str) -> bool:
        """
        Check if user exists by email.
        
        Args:
            email: User email
            
        Returns:
            True if user exists, False otherwise
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            statement = select(User.id).where(User.email == email)
            result = await self.session.execute(statement)
            return result.scalar_one_or_none() is not None
        except Exception as e:
            raise DatabaseError(f"Failed to check user existence by email: {str(e)}") from e
    
    async def exists_by_username(self, username: str) -> bool:
        """
        Check if user exists by username.
        
        Args:
            username: Username
            
        Returns:
            True if user exists, False otherwise
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            statement = select(User.id).where(User.username == username)
            result = await self.session.execute(statement)
            return result.scalar_one_or_none() is not None
        except Exception as e:
            raise DatabaseError(f"Failed to check user existence by username: {str(e)}") from e
```

```python
# src/exceptions.py
class UserManagementError(Exception):
    """Base exception for user management operations."""
    pass


class UserNotFoundError(UserManagementError):
    """Raised when user is not found."""
    pass


class UserAlreadyExistsError(UserManagementError):
    """Raised when user already exists."""
    pass


class DatabaseError(UserManagementError):
    """Raised when database operation fails."""
    pass
```

```python
# src/services/user_service.py
from typing import List, Optional
from passlib.context import CryptContext
from ..repositories.user_repository import UserRepositoryInterface
from ..models.user import User, UserCreate, UserUpdate, UserRead
from ..exceptions import UserNotFoundError


class UserService:
    """Service layer for user operations."""
    
    def __init__(self, user_repository: UserRepositoryInterface):
        self.user_repository = user_repository
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def _hash_password(self, password: str) -> str:
        """Hash password."""
        return self.pwd_context.hash(password)
    
    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password."""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    async def create_user(self, user_data: UserCreate) -> UserRead:
        """
        Create a new user.
        
        Args:
            user_data: User creation data
            
        Returns:
            Created user data
        """
        # Hash password
        hashed_user_data = user_data.copy()
        hashed_user_data.password = self._hash_password(user_data.password)
        
        user = await self.user_repository.create(hashed_user_data)
        return UserRead.from_orm(user)
    
    async def get_user_by_id(self, user_id: int) -> UserRead:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User data
            
        Raises:
            UserNotFoundError: If user not found
        """
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        return UserRead.from_orm(user)
    
    async def get_user_by_email(self, email: str) -> Optional[UserRead]:
        """
        Get user by email.
        
        Args:
            email: User email
            
        Returns:
            User data if found, None otherwise
        """
        user = await self.user_repository.get_by_email(email)
        return UserRead.from_orm(user) if user else None
    
    async def get_user_by_username(self, username: str) -> Optional[UserRead]:
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User data if found, None otherwise
        """
        user = await self.user_repository.get_by_username(username)
        return UserRead.from_orm(user) if user else None
    
    async def get_all_users(self, skip: int = 0, limit: int = 100) -> List[UserRead]:
        """
        Get all users with pagination.
        
        Args:
            skip: Number of records to skip