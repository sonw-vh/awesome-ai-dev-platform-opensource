"""
IDOR Vulnerability Fix for Model Marketplace Tasks API

This file contains the fixed Django views for the model marketplace tasks endpoints
that were vulnerable to Insecure Direct Object Reference (IDOR) attacks.

Vulnerable Endpoints:
- POST /api/model_marketplace_tasks/{model_id} - Assign tasks to model
- DELETE /api/model_marketplace_tasks/{model_id} - Unassign tasks from model

The fix adds proper authorization checks to ensure users can only manage tasks
for models they own or have permission to access.
"""

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.contrib.auth.models import User
import logging

logger = logging.getLogger(__name__)

# Model imports (adjust based on actual model structure)
# from .models import ModelMarketplace, ModelTask, ModelMarketplaceTask

class ModelOwnershipPermission:
    """
    Custom permission class to check if user owns the model
    """
    
    @staticmethod
    def has_model_permission(user, model_id):
        """
        Check if user has permission to access the model
        
        Args:
            user: The authenticated user
            model_id: The model ID to check
            
        Returns:
            bool: True if user has permission, False otherwise
        """
        try:
            # Get the model and check ownership
            model = ModelMarketplace.objects.get(id=model_id)
            
            # Check if user is the owner
            if model.owner == user:
                return True
                
            # Check if user is in the same organization (if applicable)
            if hasattr(model, 'organization') and model.organization:
                if user in model.organization.members.all():
                    return True
                    
            # Check if model is public and user has read access
            if hasattr(model, 'is_public') and model.is_public:
                return True
                
            # Add any other permission checks as needed
            return False
            
        except ModelMarketplace.DoesNotExist:
            logger.warning(f"Model {model_id} not found for user {user.id}")
            return False
        except Exception as e:
            logger.error(f"Error checking model permission: {e}")
            return False

def validate_model_ownership(user, model_id):
    """
    Validate that the user owns the model
    
    Args:
        user: The authenticated user
        model_id: The model ID to validate
        
    Returns:
        tuple: (is_valid, model_object, error_message)
    """
    try:
        model = get_object_or_404(ModelMarketplace, id=model_id)
        
        # Check ownership
        if model.owner != user:
            # Check organization membership if applicable
            if hasattr(model, 'organization') and model.organization:
                if user not in model.organization.members.all():
                    return False, None, "You don't have permission to access this model"
            else:
                return False, None, "You don't have permission to access this model"
        
        return True, model, None
        
    except ModelMarketplace.DoesNotExist:
        return False, None, "Model not found"
    except Exception as e:
        logger.error(f"Error validating model ownership: {e}")
        return False, None, "Error validating model access"

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def assign_model_tasks(request, model_id):
    """
    Assign tasks to a model (FIXED VERSION)
    
    This endpoint was vulnerable to IDOR - now includes proper authorization
    
    Args:
        request: Django request object
        model_id: The model ID from URL
        
    Returns:
        Response: JSON response with success/error
    """
    try:
        # Validate model ownership
        is_valid, model, error_msg = validate_model_ownership(request.user, model_id)
        
        if not is_valid:
            logger.warning(f"IDOR attempt blocked: User {request.user.id} tried to access model {model_id}")
            return Response(
                {"detail": error_msg or "Access denied"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get task IDs from request body
        task_ids = request.data.get('task_ids', [])
        
        if not isinstance(task_ids, list):
            return Response(
                {"detail": "task_ids must be a list"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate task IDs exist and user has access
        valid_task_ids = []
        for task_id in task_ids:
            try:
                task = ModelTask.objects.get(id=task_id)
                # Check if user has access to this task
                if task.owner == request.user or task.is_public:
                    valid_task_ids.append(task_id)
                else:
                    logger.warning(f"User {request.user.id} tried to assign task {task_id} they don't own")
            except ModelTask.DoesNotExist:
                logger.warning(f"Task {task_id} not found")
                continue
        
        # Assign tasks to model
        with transaction.atomic():
            for task_id in valid_task_ids:
                ModelMarketplaceTask.objects.update_or_create(
                    model=model,
                    task_id=task_id,
                    defaults={'assigned_by': request.user}
                )
        
        logger.info(f"User {request.user.id} assigned {len(valid_task_ids)} tasks to model {model_id}")
        
        return Response(
            {"detail": "Tasks assigned successfully", "assigned_count": len(valid_task_ids)},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Error in assign_model_tasks: {e}")
        return Response(
            {"detail": "Internal server error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def unassign_model_tasks(request, model_id):
    """
    Unassign tasks from a model (FIXED VERSION)
    
    This endpoint was vulnerable to IDOR - now includes proper authorization
    
    Args:
        request: Django request object
        model_id: The model ID from URL
        
    Returns:
        Response: JSON response with success/error
    """
    try:
        # Validate model ownership
        is_valid, model, error_msg = validate_model_ownership(request.user, model_id)
        
        if not is_valid:
            logger.warning(f"IDOR attempt blocked: User {request.user.id} tried to access model {model_id}")
            return Response(
                {"detail": error_msg or "Access denied"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get task IDs from request body
        task_ids = request.data.get('task_ids', [])
        
        if not isinstance(task_ids, list):
            return Response(
                {"detail": "task_ids must be a list"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # If task_ids is empty, unassign all tasks from the model
        if not task_ids:
            # Unassign all tasks from this model
            unassigned_count = ModelMarketplaceTask.objects.filter(model=model).count()
            ModelMarketplaceTask.objects.filter(model=model).delete()
            
            logger.info(f"User {request.user.id} unassigned all tasks from model {model_id}")
            
            return Response(
                {"detail": "All tasks unassigned successfully", "unassigned_count": unassigned_count},
                status=status.HTTP_200_OK
            )
        
        # Unassign specific tasks
        unassigned_count = 0
        for task_id in task_ids:
            try:
                task = ModelTask.objects.get(id=task_id)
                # Check if user has access to this task
                if task.owner == request.user or task.is_public:
                    deleted_count, _ = ModelMarketplaceTask.objects.filter(
                        model=model,
                        task_id=task_id
                    ).delete()
                    unassigned_count += deleted_count
                else:
                    logger.warning(f"User {request.user.id} tried to unassign task {task_id} they don't own")
            except ModelTask.DoesNotExist:
                logger.warning(f"Task {task_id} not found")
                continue
        
        logger.info(f"User {request.user.id} unassigned {unassigned_count} tasks from model {model_id}")
        
        return Response(
            {"detail": "Tasks unassigned successfully", "unassigned_count": unassigned_count},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Error in unassign_model_tasks: {e}")
        return Response(
            {"detail": "Internal server error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Additional security middleware
class IDORProtectionMiddleware:
    """
    Middleware to add additional IDOR protection
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Add security headers
        response = self.get_response(request)
        
        # Add security headers to prevent IDOR attacks
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        
        return response

# Rate limiting decorator
from django.core.cache import cache
from django.http import JsonResponse

def rate_limit(max_requests=10, window_seconds=60):
    """
    Rate limiting decorator to prevent automated attacks
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            # Create a unique key for this user and endpoint
            key = f"rate_limit_{request.user.id}_{request.path}"
            
            # Get current request count
            current_requests = cache.get(key, 0)
            
            if current_requests >= max_requests:
                logger.warning(f"Rate limit exceeded for user {request.user.id} on {request.path}")
                return JsonResponse(
                    {"detail": "Rate limit exceeded. Please try again later."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Increment counter
            cache.set(key, current_requests + 1, window_seconds)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

# Apply rate limiting to the vulnerable endpoints
@rate_limit(max_requests=20, window_seconds=60)
def assign_model_tasks_rate_limited(request, model_id):
    return assign_model_tasks(request, model_id)

@rate_limit(max_requests=20, window_seconds=60)
def unassign_model_tasks_rate_limited(request, model_id):
    return unassign_model_tasks(request, model_id)

# URL patterns (add to urls.py)
"""
urlpatterns = [
    path('api/model_marketplace_tasks/<int:model_id>/', assign_model_tasks_rate_limited, name='assign_model_tasks'),
    path('api/model_marketplace_tasks/<int:model_id>/', unassign_model_tasks_rate_limited, name='unassign_model_tasks'),
]
"""
