import { Inject, Injectable, OnModuleDestroy } from "@nestjs/common";
import { Pool, QueryResult, QueryResultRow } from "pg";
import { AppConfig, CONFIG } from "../config";

@Injectable()
export class DbService implements OnModuleDestroy {
  private readonly pool: Pool;

  constructor(@Inject(CONFIG) config: AppConfig) {
    this.pool = new Pool({ connectionString: config.databaseUrl });
  }

  query<T extends QueryResultRow = QueryResultRow>(text: string, params: unknown[] = []): Promise<QueryResult<T>> {
    return this.pool.query<T>(text, params);
  }

  async tx<T>(work: (query: <R extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]) => Promise<QueryResult<R>>) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await work((text, params = []) => client.query(text, params));
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}
