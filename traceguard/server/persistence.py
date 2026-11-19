"""Persistence boundary for interactive detections and validation state."""

import json

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

from .store import utcnow


class SQLitePersistence:
    provider = "SQLITE LOCAL"

    def __init__(self, store):
        self.store = store
        self.engine = create_engine(
            URL.create("sqlite", database=store.path),
            connect_args={"check_same_thread": False},
        )

    @staticmethod
    def _statement(sql, params=()):
        """Bind legacy qmark statements through SQLAlchemy's text interface."""
        values = iter(params)
        index = 0
        pieces = sql.split("?")
        if len(pieces) > 1:
            sql = pieces[0]
            bindings = {}
            for piece in pieces[1:]:
                name = f"p{index}"
                bindings[name] = next(values)
                sql += f":{name}" + piece
                index += 1
            return text(sql), bindings
        return text(sql), params

    def health(self):
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1 AS ok")).first()
        return True

    def save_evaluation(self, payload, result):
        with self.engine.begin() as connection:
            sql, values = self._statement(
                "INSERT INTO eval_history (evaluation_id, created_utc, key_id, user_agent, caller_ip, verdict, risk_score, triggered_rules, canary, payload, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result["evaluation_id"], result["timestamp"], payload.key_id, payload.user_agent,
                 payload.caller_ip or "", result["verdict"], result["risk_score"],
                 json.dumps(result["triggered_rules"]), int(result["canary"]),
                 payload.model_dump_json(), json.dumps(result)),
            )
            connection.execute(sql, values)
            if result["canary"]:
                sql, values = self._statement(
                    "INSERT INTO canary_alerts (evaluation_id, created_utc, key_id, payload) VALUES (?, ?, ?, ?)",
                    (result["evaluation_id"], result["timestamp"], payload.key_id, payload.model_dump_json()),
                )
                connection.execute(sql, values)

    def history(self, limit):
        sql, values = self._statement("SELECT evaluation_id, created_utc AS timestamp, key_id, user_agent, caller_ip, verdict, risk_score, triggered_rules, canary FROM eval_history ORDER BY created_utc DESC LIMIT ?", (limit,))
        with self.engine.connect() as connection:
            rows = [dict(row) for row in connection.execute(sql, values).mappings().all()]
        for row in rows:
            row["triggered_rules"] = json.loads(row["triggered_rules"])
            row["canary"] = bool(row["canary"])
        return rows

    def get_validation(self):
        with self.engine.connect() as connection:
            row = connection.execute(text("SELECT * FROM validation_state WHERE id = 1")).mappings().first()
            return dict(row) if row else None

    def save_validation(self, payload):
        sql, values = self._statement("INSERT INTO validation_state (id, true_positives, false_positives, missed_detections, evidence_row_ids, metadata, updated_utc) VALUES (1, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET true_positives=excluded.true_positives, false_positives=excluded.false_positives, missed_detections=excluded.missed_detections, evidence_row_ids=excluded.evidence_row_ids, metadata=excluded.metadata, updated_utc=excluded.updated_utc",
                                       (payload.true_positives, payload.false_positives, payload.missed_detections, json.dumps(payload.evidence_row_ids), json.dumps(payload.metadata), utcnow()))
        with self.engine.begin() as connection:
            connection.execute(sql, values)
        return self.get_validation()

    def references(self):
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(text("SELECT evidence_id, row_reference, updated_utc FROM evidence_references ORDER BY evidence_id")).mappings().all()]

    def save_references(self, refs):
        sql = text("INSERT INTO evidence_references (evidence_id, row_reference, updated_utc) VALUES (:evidence_id, :row_reference, :updated_utc) ON CONFLICT(evidence_id) DO UPDATE SET row_reference=excluded.row_reference, updated_utc=excluded.updated_utc")
        with self.engine.begin() as connection:
            connection.execute(sql, [{"evidence_id": evidence_id, "row_reference": reference, "updated_utc": utcnow()} for evidence_id, reference in refs.items()])
        return self.references()

    def checklist(self):
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(text("SELECT item_id, checked, updated_utc FROM checklist_state ORDER BY item_id")).mappings().all()]

    def save_checklist(self, item_id, checked):
        sql, values = self._statement("INSERT INTO checklist_state (item_id, checked, updated_utc) VALUES (?, ?, ?) ON CONFLICT(item_id) DO UPDATE SET checked=excluded.checked, updated_utc=excluded.updated_utc", (item_id, int(checked), utcnow()))
        with self.engine.begin() as connection:
            connection.execute(sql, values)


class SupabasePersistence:
    """Uses documented Supabase tables and does not switch providers on error."""
    provider = "SUPABASE CONNECTED"

    def __init__(self, client):
        self.client = client

    def health(self):
        self.client.table("evaluation_history").select("id").limit(1).execute()
        return True

    def save_evaluation(self, payload, result):
        self.client.table("evaluation_history").insert({
            "id": result["evaluation_id"], "created_utc": result["timestamp"],
            "key_id": payload.key_id, "user_agent": payload.user_agent,
            "caller_ip": payload.caller_ip or "", "verdict": result["verdict"],
            "risk_score": result["risk_score"], "triggered_rules": result["triggered_rules"],
            "canary": result["canary"], "payload": payload.model_dump(), "result": result,
        }).execute()
        if result["canary"]:
            self.client.table("canary_alerts").insert({"evaluation_id": result["evaluation_id"], "created_utc": result["timestamp"], "key_id": payload.key_id, "payload": payload.model_dump()}).execute()

    def history(self, limit):
        return self.client.table("evaluation_history").select("id,created_utc,key_id,user_agent,caller_ip,verdict,risk_score,triggered_rules,canary").order("created_utc", desc=True).limit(limit).execute().data

    def get_validation(self):
        rows = self.client.table("validation_metrics").select("*").eq("id", 1).limit(1).execute().data
        return rows[0] if rows else None

    def save_validation(self, payload):
        self.client.table("validation_metrics").upsert({"id": 1, **payload.model_dump(), "updated_utc": utcnow()}).execute()
        return self.get_validation()

    def references(self):
        return self.client.table("evidence_references").select("evidence_id,row_reference,updated_utc").order("evidence_id").execute().data

    def save_references(self, refs):
        self.client.table("evidence_references").upsert([{"evidence_id": k, "row_reference": v, "updated_utc": utcnow()} for k, v in refs.items()]).execute()
        return self.references()

    def checklist(self):
        return self.client.table("evidence_checklist").select("item_id,checked,updated_utc").order("item_id").execute().data

    def save_checklist(self, item_id, checked):
        self.client.table("evidence_checklist").upsert({"item_id": item_id, "checked": checked, "updated_utc": utcnow()}).execute()
