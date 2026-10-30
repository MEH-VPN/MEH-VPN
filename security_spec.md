# Security Specification (`security_spec.md`)

## 1. Data Invariants
- All data is stored under `/users/{userId}/connection_logs/{logId}`.
- Every operation (`get`, `list`, `create`, `update`, `delete`) requires an authenticated user (`request.auth != null`) whose `request.auth.uid == userId`.
- Document IDs (`userId` and `logId`) for single-document operations must match `^[a-zA-Z0-9_\-]+$` with length `1..128`.
- `userId` inside the document payload must equal `request.auth.uid` and `userId` path parameter, and is immutable on update.
- `createdAt` must be a valid server `timestamp` (`<= request.time`) and is immutable on update.
- String lengths are strictly bounded (`countryNameFa <= 60`, `flagEmoji <= 20`, `rawUri <= 2048`, `sourceRepo <= 200`), and `pingMs` is an integer in `0..60000`.
- Only allowlisted keys (`userId`, `countryNameFa`, `flagEmoji`, `rawUri`, `sourceRepo`, `pingMs`, `createdAt`, `updatedAt`) are permitted.

## 2. The "Dirty Dozen" Payloads
1. **Unauthenticated Read**: `unauthDb.doc("users/alice_123/connection_logs/log_1").get()` -> Reject
2. **Unauthenticated Write**: `unauthDb.doc("users/alice_123/connection_logs/log_1").set(...)` -> Reject
3. **Cross-User Read**: `aliceDb.doc("users/bob_456/connection_logs/log_1").get()` -> Reject
4. **Cross-User List**: `aliceDb.collection("users/bob_456/connection_logs").get()` -> Reject
5. **Cross-User Write**: `aliceDb.doc("users/bob_456/connection_logs/log_1").set(...)` -> Reject
6. **Spoofed Payload `userId`**: `aliceDb.doc("users/alice_123/connection_logs/log_1").set({ userId: "bob_456", ... })` -> Reject
7. **Shadow Field Injection**: Payload including `{ ..., isAdmin: true }` -> Reject via `hasOnly`
8. **Missing Required Key**: Payload omitting `rawUri` or `createdAt` -> Reject via `hasAll`
9. **Oversized String**: `rawUri` of 5000 characters -> Reject via `size() <= 2048`
10. **Negative or Out-of-Range `pingMs`**: `pingMs: -5` or `pingMs: 999999` -> Reject
11. **Immutable `createdAt` Tampering on Update**: Updating `createdAt` to a different timestamp -> Reject
12. **Immutable `userId` Tampering on Update**: Updating `userId` to another user -> Reject
