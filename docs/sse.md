# SSE stream: workspace authorization contract

Отдельный контракт на HTTP surface (plan 89-workspace-roles, Task 3).
SSE stream сознательно **не входит в OpenAPI paths** и **не является MCP
tool**: это длительное соединение `routes/web.php` (без `/api/` prefix),
а не операция с request/response семантикой. Всё остальное workspace
поведение специфицировано в `openapi.yaml`.

## Селектор workspace (D1)

- Native `EventSource` не умеет кастомные заголовки, поэтому SSE передаёт
  public ULID workspace в query-параметре `workspace`. Это **не credential**
  и не альтернативный канал авторизации: server сводит оба транспорта
  (заголовок REST, query SSE) к одному resolver.
- Конфликт транспорта отклоняется: `workspace` query + `X-Workspace-Id`
  header одновременно → 409, precedence не угадывается.
- Пропуск селектора — legacy поведение: только personal workspace того же
  actor, независимо от последнего выбора UI и количества memberships.
- Чужой/неверный селектор никогда не вызывает personal fallback —
  соединение не устанавливается (safe 403/404, идентичные отсутствующему).

## Отзыв доступа (D2 revocation policy)

- Authority перепроверяется: на подключение, на **каждый** data frame и на
  каждый heartbeat (wall-clock check, включая непрерывный поток и тишину).
- После commit revoke/downgrade/removal/PAT revoke/archive stream
  прекращает отправку данных и закрывается **не позднее 5 секунд**
  (contract target для измерения, не текущее SLA). Revalidation failure —
  fail-closed.
- Уже отправленные bytes не отзываются ретроактивно; новые frames после
  deadline запрещены.
- Reconnect после отзыва — denied (обычный 401/403/404 REST semantics);
  клиент не ретраит бесконечно на auth-ошибках.

## Ограничения транспорта

- Bounded wall-clock lifetime: MAX_LIFETIME=300s, подчинён принятому
  revocation сроку; quiet-timeout не продлевает жизнь неавторизованного
  stream.
- Redis failure/abort обрабатываются в bounded времени без расширения
  доступа.
- Close reason — bounded и safe: без чужих resource details.

## Инварианты

- Membership role ∩ PAT abilities проверяются на server; UI/MCP не
  предоставляют разрешение.
- Поток не переключает active context: один request — один workspace.
- Логи stream — bounded: event/duration/reason, без payload.
