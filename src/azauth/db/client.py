from __future__ import annotations

import logging
from typing import Any

from neo4j import GraphDatabase

log = logging.getLogger(__name__)

DEFAULT_URI = "bolt://localhost:7687"
DEFAULT_USER = "neo4j"
DEFAULT_PASSWORD = "azauth_neo4j"


class Neo4jConnection:
    def __init__(
        self,
        uri: str = DEFAULT_URI,
        user: str = DEFAULT_USER,
        password: str = DEFAULT_PASSWORD,
        database: str = "neo4j",
    ):
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self._driver: GraphDatabase.driver | None = None

    def connect(self) -> None:
        if self._driver:
            return
        self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        self._driver.verify_connectivity()
        log.info("Connected to Neo4j at %s", self.uri)

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None

    def run(self, query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        if not self._driver:
            self.connect()
        with self._driver.session(database=self.database) as session:
            result = session.run(query, params or {})
            return [r.data() for r in result]

    def run_in_tx(self, query: str, params: dict[str, Any] | None = None) -> None:
        if not self._driver:
            self.connect()
        with self._driver.session(database=self.database) as session:
            session.execute_write(lambda tx: tx.run(query, params or {}))

    def __enter__(self) -> Neo4jConnection:
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
