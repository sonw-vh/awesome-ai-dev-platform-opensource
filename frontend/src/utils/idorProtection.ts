/**
 * IDOR Protection Utility
 * 
 * This utility provides client-side protection against Insecure Direct Object Reference (IDOR)
 * attacks by validating model ownership before making API requests.
 */

import { useApi } from "@/providers/ApiProvider";

export interface ModelOwnershipInfo {
  modelId: number;
  isOwner: boolean;
  canManage: boolean;
  error?: string;
}

/**
 * Validates if the current user owns or can manage a specific model
 * @param modelId - The model ID to validate
 * @returns Promise<ModelOwnershipInfo> - Ownership information
 */
export const validateModelOwnership = async (modelId: number): Promise<ModelOwnershipInfo> => {
  try {
    // First, try to get the model details to check ownership
    const response = await fetch(`/api/model_marketplace/${modelId}/`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        return {
          modelId,
          isOwner: false,
          canManage: false,
          error: 'Model not found'
        };
      }
      
      if (response.status === 403) {
        return {
          modelId,
          isOwner: false,
          canManage: false,
          error: 'Access denied - you do not have permission to access this model'
        };
      }
      
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const modelData = await response.json();
    
    // Check if current user is the owner
    const currentUserId = getCurrentUserId();
    const isOwner = modelData.owner === currentUserId || modelData.owner_id === currentUserId;
    
    // Check if user can manage (owner or admin)
    const canManage = isOwner || modelData.can_manage || false;

    return {
      modelId,
      isOwner,
      canManage,
      error: canManage ? undefined : 'You do not have permission to manage this model'
    };

  } catch (error) {
    console.error('Error validating model ownership:', error);
    return {
      modelId,
      isOwner: false,
      canManage: false,
      error: 'Error validating model access'
    };
  }
};

/**
 * Gets the current user ID from stored authentication data
 * @returns number | null - Current user ID or null if not found
 */
const getCurrentUserId = (): number | null => {
  try {
    // Try to get user ID from various sources
    const userData = localStorage.getItem('user_data');
    if (userData) {
      const parsed = JSON.parse(userData);
      return parsed.id || parsed.user_id || null;
    }
    
    // Try to get from token payload (if JWT)
    const token = localStorage.getItem('access_token');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.user_id || payload.id || null;
      } catch (e) {
        // Token is not JWT or invalid
      }
    }
    
    return null;
  } catch (error) {
    console.error('Error getting current user ID:', error);
    return null;
  }
};

/**
 * Safe wrapper for model task assignment with IDOR protection
 * @param modelId - The model ID
 * @param taskIds - Array of task IDs to assign
 * @returns Promise<Response> - API response
 */
export const safeAssignModelTasks = async (modelId: number, taskIds: number[]): Promise<Response> => {
  // Validate ownership first
  const ownership = await validateModelOwnership(modelId);
  
  if (!ownership.canManage) {
    throw new Error(ownership.error || 'Access denied');
  }

  // Make the API request
  return fetch(`/api/model_marketplace_tasks/${modelId}/`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ task_ids: taskIds })
  });
};

/**
 * Safe wrapper for model task unassignment with IDOR protection
 * @param modelId - The model ID
 * @param taskIds - Array of task IDs to unassign (empty array for all)
 * @returns Promise<Response> - API response
 */
export const safeUnassignModelTasks = async (modelId: number, taskIds: number[]): Promise<Response> => {
  // Validate ownership first
  const ownership = await validateModelOwnership(modelId);
  
  if (!ownership.canManage) {
    throw new Error(ownership.error || 'Access denied');
  }

  // Make the API request
  return fetch(`/api/model_marketplace_tasks/${modelId}/`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ task_ids: taskIds })
  });
};

/**
 * React hook for safe model task management
 */
export const useSafeModelTaskManagement = () => {
  const api = useApi();

  const assignTasks = async (modelId: number, taskIds: number[]) => {
    try {
      const response = await safeAssignModelTasks(modelId, taskIds);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error assigning model tasks:', error);
      throw error;
    }
  };

  const unassignTasks = async (modelId: number, taskIds: number[] = []) => {
    try {
      const response = await safeUnassignModelTasks(modelId, taskIds);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error unassigning model tasks:', error);
      throw error;
    }
  };

  return {
    assignTasks,
    unassignTasks,
    validateModelOwnership
  };
};

/**
 * IDOR Attack Detection
 * Monitors for suspicious patterns that might indicate IDOR attacks
 */
export class IDORAttackDetector {
  private static instance: IDORAttackDetector;
  private suspiciousActivity: Map<string, number> = new Map();
  private readonly THRESHOLD = 10; // Max requests per minute
  private readonly WINDOW = 60000; // 1 minute in milliseconds

  static getInstance(): IDORAttackDetector {
    if (!IDORAttackDetector.instance) {
      IDORAttackDetector.instance = new IDORAttackDetector();
    }
    return IDORAttackDetector.instance;
  }

  /**
   * Records a model access attempt
   * @param modelId - The model ID being accessed
   * @param userId - The user ID making the request
   */
  recordAccess(modelId: number, userId: number): boolean {
    const key = `${userId}_${modelId}`;
    const now = Date.now();
    const windowStart = now - this.WINDOW;

    // Clean old entries
    for (const [k, timestamp] of this.suspiciousActivity.entries()) {
      if (timestamp < windowStart) {
        this.suspiciousActivity.delete(k);
      }
    }

    // Count requests in current window
    const currentCount = Array.from(this.suspiciousActivity.entries())
      .filter(([k, timestamp]) => k.startsWith(`${userId}_`) && timestamp > windowStart)
      .length;

    if (currentCount >= this.THRESHOLD) {
      console.warn(`Potential IDOR attack detected: User ${userId} made ${currentCount} requests in ${this.WINDOW}ms`);
      this.reportSuspiciousActivity(userId, currentCount);
      return false; // Block the request
    }

    // Record this access
    this.suspiciousActivity.set(key, now);
    return true; // Allow the request
  }

  private reportSuspiciousActivity(userId: number, requestCount: number): void {
    // In a real application, this would send data to a security monitoring system
    console.error(`SECURITY ALERT: Potential IDOR attack by user ${userId} - ${requestCount} requests in ${this.WINDOW}ms`);
    
    // Could send to monitoring service
    // monitoringService.reportSecurityIncident({
    //   type: 'IDOR_ATTACK',
    //   userId,
    //   requestCount,
    //   timestamp: new Date().toISOString()
    // });
  }
}

export default {
  validateModelOwnership,
  safeAssignModelTasks,
  safeUnassignModelTasks,
  useSafeModelTaskManagement,
  IDORAttackDetector
};
