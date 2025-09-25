import React, { useCallback, useRef } from "react";
import { useApi } from "@/providers/ApiProvider";
import useDebouncedEffect from "../useDebouncedEffect";
import { TModelTask, TModelTasks, validateModelTasksModel } from "@/models/modelMarketplace";
import { extractErrorMessage } from "@/utils/error";
import { useSafeModelTaskManagement, IDORAttackDetector } from "@/utils/idorProtection";

export default function useModelTasks() {
  const [list, setList] = React.useState<TModelTasks>([]);
  const [initialized, setInitialized] = React.useState<boolean>(false);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [loadingError, setLoadingError] = React.useState<null | string>(null);
  const listCtrlRef = useRef<AbortController | null>(null);
  const api = useApi();
  
  // IDOR Protection
  const { assignTasks: safeAssignTasks, unassignTasks: safeUnassignTasks } = useSafeModelTaskManagement();
  const attackDetector = IDORAttackDetector.getInstance();

  const refresh = useCallback(() => {
    listCtrlRef.current && !listCtrlRef.current?.signal.aborted && listCtrlRef.current?.abort("New request");
    setLoading(true);
    setLoadingError(null);

    const ar = api.call("modelTasks");
    listCtrlRef.current = ar.controller;

    ar.promise
      .then(async r => {
        if (ar.controller.signal.aborted) return;
        const data = await r.json();
        const vr = validateModelTasksModel(data);

        if (vr.isValid) {
          setList(vr.data);
          setLoadingError(null);
        } else {
          setLoadingError("Invalid model tasks list received from the server. Please try again!");
          window.APP_SETTINGS.debug && console.error(vr);
        }
      })
      .catch(e => {
        if (ar.controller.signal.aborted) return;
        setLoadingError("An error occurred while loading tasks list." + extractErrorMessage(e));
        window.APP_SETTINGS.debug && console.error(e);
      })
      .finally(() => {
        if (ar.controller.signal.aborted) return;
        setLoading(false);
        setInitialized(true);
        listCtrlRef.current = null;
      });

    return ar;
  }, [api]);

  const create = useCallback((body: Exclude<TModelTask, "id" | "created_at" | "updated_at">) => {
    return api.call("addModelTasks", {body});
  }, [api]);

  const update = useCallback((id: number, body: Exclude<TModelTask, "id" | "created_at" | "updated_at">) => {
    return api.call("updateModelTasks", {
      params: {
        id: id.toString(),
      },
      body,
    });
  }, [api]);

  const remove = useCallback((id: number) => {
    return api.call("deleteModelTasks", {
      params: {
        id: id.toString(),
      },
    });
  }, [api]);

  const assignTasks = useCallback(async (modelID: number, modelTaskIds: number[]) => {
    try {
      // Check for potential IDOR attack
      const currentUserId = getCurrentUserId();
      if (currentUserId && !attackDetector.recordAccess(modelID, currentUserId)) {
        throw new Error("Too many requests. Please slow down.");
      }

      // Use safe assignment with IDOR protection
      const result = await safeAssignTasks(modelID, modelTaskIds);
      return { data: result };
    } catch (error) {
      console.error("Error in assignTasks:", error);
      throw error;
    }
  }, [safeAssignTasks, attackDetector]);

  const unassignTasks = useCallback(async (modelID: number, modelTaskIds: number[]) => {
    try {
      // Check for potential IDOR attack
      const currentUserId = getCurrentUserId();
      if (currentUserId && !attackDetector.recordAccess(modelID, currentUserId)) {
        throw new Error("Too many requests. Please slow down.");
      }

      // Use safe unassignment with IDOR protection
      const result = await safeUnassignTasks(modelID, modelTaskIds);
      return { data: result };
    } catch (error) {
      console.error("Error in unassignTasks:", error);
      throw error;
    }
  }, [safeUnassignTasks, attackDetector]);

  // Helper function to get current user ID
  const getCurrentUserId = (): number | null => {
    try {
      const userData = localStorage.getItem('user_data');
      if (userData) {
        const parsed = JSON.parse(userData);
        return parsed.id || parsed.user_id || null;
      }
      return null;
    } catch (error) {
      console.error('Error getting current user ID:', error);
      return null;
    }
  };

  useDebouncedEffect(() => {
    const ar = refresh();

    return () => {
      !ar.controller.signal.aborted && ar.controller.abort();
    }
  }, [api, refresh]);

  return React.useMemo(() => {
    return {
      list,
      initialized,
      loading,
      loadingError,
      refresh,
      create,
      update,
      remove,
      assignTasks,
      unassignTasks,
    }
  }, [
    list,
    initialized,
    loading,
    loadingError,
    refresh,
    create,
    update,
    remove,
    assignTasks,
    unassignTasks,
  ]);
}
