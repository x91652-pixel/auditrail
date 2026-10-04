"""Policy and guarded tool wiring for the simulated logistics company.

Five agents run the company's operations. Each agent gets only the tools
its job needs (default-deny), and every tool is tagged with the risk
categories it touches, so the lethal-trifecta rule applies per session.
"""
from __future__ import annotations

from auditrail.agent_bridge import ReplayGuard, verify_message

from . import tools as t

POLICY = {
    "version": "logistics-policy-v1-2026Q4",
    "agents": {
        "dispatcher-agent": {
            "allowed_tools": ["lookup_shipment", "read_carrier_status", "reroute_shipment",
                              "notify_customer", "call_warehouse_agent"],
            "tool_categories": {
                "lookup_shipment": ["data_access"],
                "read_carrier_status": ["untrusted_input"],
                "reroute_shipment": [],
                "notify_customer": ["external_comm"],
                "call_warehouse_agent": ["agent_to_agent"],
            },
            "enforce_lethal_trifecta": True,
        },
        "customer-service-agent": {
            "allowed_tools": ["read_customer_note", "read_customer_record", "reply_customer",
                              "lookup_shipment"],
            "tool_categories": {
                "read_customer_note": ["untrusted_input"],
                "read_customer_record": ["data_access"],
                "reply_customer": ["external_comm"],
                "lookup_shipment": ["data_access"],
            },
            "enforce_lethal_trifecta": True,
        },
        "warehouse-agent": {
            "allowed_tools": ["scan_pallet", "update_inventory", "call_dispatcher_agent"],
            "tool_categories": {
                "scan_pallet": [],
                "update_inventory": [],
                "call_dispatcher_agent": ["agent_to_agent"],
            },
            "enforce_lethal_trifecta": True,
        },
        "finance-agent": {
            "allowed_tools": ["read_invoice", "issue_refund"],
            "tool_categories": {
                "read_invoice": ["data_access"],
                "issue_refund": [],
            },
            "enforce_lethal_trifecta": True,
        },
        "sandbox-probe-agent": {
            # Deliberately has a sandboxed tool, to test secret isolation and timeouts.
            "allowed_tools": ["probe_carrier_api_key", "slow_sync_job"],
            "tool_categories": {"probe_carrier_api_key": [], "slow_sync_job": []},
            "enforce_lethal_trifecta": True,
        },
    },
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}


def build(guard, bridge_secret: str, replay_guard: ReplayGuard):
    """Return the company's tools, each wrapped by the given Guard.

    Keys are tool names. Calls look like: tools["lookup_shipment"](session, "SHP-1001").
    Agent-to-agent tools verify a signed envelope before acting on it.
    """
    g = guard.guarded_tool

    def _deliver(target: str, envelope: dict) -> dict:
        payload = verify_message(envelope, bridge_secret, replay_guard=replay_guard)
        return {"delivered_to": target, "payload": payload}

    def call_warehouse_agent(envelope: dict) -> dict:
        return _deliver("warehouse-agent", envelope)

    def call_dispatcher_agent(envelope: dict) -> dict:
        return _deliver("dispatcher-agent", envelope)

    return {
        "call_warehouse_agent": g("call_warehouse_agent", categories=["agent_to_agent"])(call_warehouse_agent),
        "call_dispatcher_agent": g("call_dispatcher_agent", categories=["agent_to_agent"])(call_dispatcher_agent),
        "lookup_shipment": g("lookup_shipment", categories=["data_access"])(t.lookup_shipment),
        "read_carrier_status": g("read_carrier_status", categories=["untrusted_input"])(t.read_carrier_status),
        "reroute_shipment": g("reroute_shipment")(t.reroute_shipment),
        "notify_customer": g("notify_customer", categories=["external_comm"])(t.notify_customer),
        "read_customer_note": g("read_customer_note", categories=["untrusted_input"])(t.read_customer_note),
        "read_customer_record": g("read_customer_record", categories=["data_access"])(t.read_customer_record),
        "reply_customer": g("reply_customer", categories=["external_comm"])(_reply_customer),
        "read_invoice": g("read_invoice", categories=["data_access"])(t.read_invoice),
        "issue_refund": g("issue_refund")(t.issue_refund),
        "scan_pallet": g("scan_pallet")(t.scan_pallet),
        "update_inventory": g("update_inventory")(t.update_inventory),
        "probe_carrier_api_key": g("probe_carrier_api_key", isolate=True, timeout=5)(t.probe_carrier_api_key),
        "slow_sync_job": g("slow_sync_job", isolate=True, timeout=1)(t.slow_sync_job),
    }


def _reply_customer(ticket_id: str, text: str) -> dict:
    """Module-level so it stays a plain function; sends via the notify path."""
    customer_id = t.TICKETS[ticket_id]["customer_id"]
    return t.notify_customer(customer_id, text)
