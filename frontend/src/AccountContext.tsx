import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api } from "@/api/client";
import type { AccountInfo } from "@/api/types";

// 계정 선택 전역 상태. selected="" 이면 전체(모든 계정 통합), 아니면 특정 account_id.
// 관제 계정을 고르면 전체가 보여야 하므로, 관제(is_tooling) 계정도 목록에 있지만 "전체"가 기본.
interface AccountCtx {
  accounts: AccountInfo[];
  selected: string; // "" = 전체
  setSelected: (a: string) => void;
  loading: boolean;
}

const Ctx = createContext<AccountCtx>({ accounts: [], selected: "", setSelected: () => {}, loading: true });

export function AccountProvider({ children }: { children: ReactNode }) {
  const [accounts, setAccounts] = useState<AccountInfo[]>([]);
  const [selected, setSelected] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getAccounts()
      .then(setAccounts)
      .catch(() => setAccounts([]))
      .finally(() => setLoading(false));
  }, []);

  return <Ctx.Provider value={{ accounts, selected, setSelected, loading }}>{children}</Ctx.Provider>;
}

export function useAccounts() {
  return useContext(Ctx);
}
