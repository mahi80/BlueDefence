// Types for the users CLI helpers the tests import (round 7 U-6).
export interface UsersFile { users: Record<string, { role: string; hash: string; disabled?: boolean }> }
export function loadUsersFile(file: string): UsersFile;
export function saveUsersFile(file: string, users: UsersFile): void;
