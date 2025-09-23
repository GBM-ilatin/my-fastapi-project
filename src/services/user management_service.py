```python
# src/services/user_service.py
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from src.models.user import User, UserCreate, UserUpdate
from src.repositories.user_repository import UserRepository
from src.core.security import get_password_hash, verify_password
import logging

logger = logging.getLogger(__name__)


class UserService:
    """Service layer for user management operations."""
    
    def __init__(self, user_repository: UserRepository):
        """
        Initialize UserService with dependency injection.
        
        Args:
            user_repository: Repository for user data operations
        """
        self.user_repository = user_repository
    
    async def create_user(self, user_data: UserCreate) -> User:
        """
        Create a new user with validation and password hashing.
        
        Args:
            user_data: User creation data
            
        Returns:
            Created user object
            
        Raises:
            HTTPException: If user already exists or validation fails
        """
        try:
            # Check if user already exists
            existing_user = await self.user_repository.get_by_email(user_data.email)
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists"
                )
            
            # Hash password
            hashed_password = get_password_hash(user_data.password)
            
            # Create user
            user_dict = user_data.dict(exclude={'password'})
            user_dict['hashed_password'] = hashed_password
            
            user = await self.user_repository.create(user_dict)
            logger.info(f"User created successfully: {user.email}")
            return user
            
        except IntegrityError as e:
            logger.error(f"Database integrity error creating user: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User creation failed due to data constraints"
            )
        except Exception as e:
            logger.error(f"Unexpected error creating user: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
    
    async def get_user_by_id(self, user_id: int) -> User:
        """
        Retrieve user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User object
            
        Raises:
            HTTPException: If user not found
        """
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return user
    
    async def get_user_by_email(self, email: str) -> User:
        """
        Retrieve user by email.
        
        Args:
            email: User email
            
        Returns:
            User object
            
        Raises:
            HTTPException: If user not found
        """
        user = await self.user_repository.get_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return user
    
    async def get_users(
        self, 
        skip: int = 0, 
        limit: int = 100,
        is_active: Optional[bool] = None
    ) -> List[User]:
        """
        Retrieve users with pagination and filtering.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            is_active: Filter by active status
            
        Returns:
            List of user objects
        """
        try:
            users = await self.user_repository.get_multi(
                skip=skip, 
                limit=limit,
                is_active=is_active
            )
            return users
        except Exception as e:
            logger.error(f"Error retrieving users: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error retrieving users"
            )
    
    async def update_user(self, user_id: int, user_data: UserUpdate) -> User:
        """
        Update user information.
        
        Args:
            user_id: User ID
            user_data: User update data
            
        Returns:
            Updated user object
            
        Raises:
            HTTPException: If user not found or update fails
        """
        try:
            # Check if user exists
            existing_user = await self.user_repository.get_by_id(user_id)
            if not existing_user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Check email uniqueness if email is being updated
            if user_data.email and user_data.email != existing_user.email:
                email_user = await self.user_repository.get_by_email(user_data.email)
                if email_user:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email already in use"
                    )
            
            # Hash new password if provided
            update_dict = user_data.dict(exclude_unset=True, exclude={'password'})
            if user_data.password:
                update_dict['hashed_password'] = get_password_hash(user_data.password)
            
            user = await self.user_repository.update(user_id, update_dict)
            logger.info(f"User updated successfully: {user.email}")
            return user
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error updating user"
            )
    
    async def delete_user(self, user_id: int) -> bool:
        """
        Delete user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            True if deletion successful
            
        Raises:
            HTTPException: If user not found or deletion fails
        """
        try:
            # Check if user exists
            existing_user = await self.user_repository.get_by_id(user_id)
            if not existing_user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            success = await self.user_repository.delete(user_id)
            if success:
                logger.info(f"User deleted successfully: {user_id}")
            return success
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error deleting user"
            )
    
    async def deactivate_user(self, user_id: int) -> User:
        """
        Deactivate user account.
        
        Args:
            user_id: User ID
            
        Returns:
            Updated user object
            
        Raises:
            HTTPException: If user not found
        """
        return await self.update_user(user_id, UserUpdate(is_active=False))
    
    async def activate_user(self, user_id: int) -> User:
        """
        Activate user account.
        
        Args:
            user_id: User ID
            
        Returns:
            Updated user object
            
        Raises:
            HTTPException: If user not found
        """
        return await self.update_user(user_id, UserUpdate(is_active=True))
    
    async def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate user with email and password.
        
        Args:
            email: User email
            password: Plain text password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        try:
            user = await self.user_repository.get_by_email(email)
            if not user:
                return None
            
            if not verify_password(password, user.hashed_password):
                return None
            
            if not user.is_active:
                return None
            
            return user
            
        except Exception as e:
            logger.error(f"Error authenticating user {email}: {str(e)}")
            return None
    
    async def get_user_count(self, is_active: Optional[bool] = None) -> int:
        """
        Get total count of users.
        
        Args:
            is_active: Filter by active status
            
        Returns:
            Total user count
        """
        try:
            return await self.user_repository.count(is_active=is_active)
        except Exception as e:
            logger.error(f"Error getting user count: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error retrieving user count"
            )
```