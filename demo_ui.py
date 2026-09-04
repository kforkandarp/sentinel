"""Streamlit demonstration client for the Sentinel AI Security Gateway."""

from pathlib import Path
import httpx
import streamlit as st

BACKEND_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="Sentinel AI Security Gateway",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Sentinel")
st.subheader("AI Security Gateway for Agentic Commerce")
st.caption("Checks untrusted content before an autonomous action can be executed.")

st.info(
    "**Core Security Principle: Detection != Authorization.** "
    "Sentinel separates threat detection from authorization. Even if malicious content is missed "
    "by the detector, PolicyGate still enforces the user's spending and task limits."
)

# -------------------------------------------------------------------------
# Session State Initialization
# -------------------------------------------------------------------------
default_content = Path("data/corpus/benign/bulk_cable_accessory_quote_009.txt").read_text(encoding="utf-8")

if "content" not in st.session_state:
    st.session_state.content = default_content
if "product_id" not in st.session_state:
    st.session_state.product_id = "cat6_cable_bulk"
if "category" not in st.session_state:
    st.session_state.category = "cable"
if "quantity" not in st.session_state:
    st.session_state.quantity = 2
if "unit_price" not in st.session_state:
    st.session_state.unit_price = 1500.00
if "allowed_categories" not in st.session_state:
    st.session_state.allowed_categories = "cable, accessory"
if "max_budget" not in st.session_state:
    st.session_state.max_budget = 5000.00
if "last_result" not in st.session_state:
    st.session_state.last_result = None

# -------------------------------------------------------------------------
# SECTION 1: Try a Scenario
# -------------------------------------------------------------------------
st.markdown("### 1. Try a Scenario")
sc1, sc2, sc3 = st.columns(3)

with sc1:
    if st.button("1. Safe purchase", use_container_width=True):
        path = Path("data/corpus/benign/bulk_cable_accessory_quote_009.txt")
        st.session_state.content = path.read_text(encoding="utf-8")
        st.session_state.product_id = "cat6_spool_1000ft"
        st.session_state.category = "cable"
        st.session_state.quantity = 2
        st.session_state.unit_price = 1500.00
        st.session_state.allowed_categories = "cable, accessory"
        st.session_state.max_budget = 5000.00
        st.session_state.last_result = None

with sc2:
    if st.button("2. Suspicious content", use_container_width=True):
        path = Path("data/corpus/adversarial/wholesale_catalog_hidden_instruction_021.txt")
        st.session_state.content = path.read_text(encoding="utf-8")
        st.session_state.product_id = "cloud_tier_compute"
        st.session_state.category = "electronics"
        st.session_state.quantity = 1
        st.session_state.unit_price = 4000.00
        st.session_state.allowed_categories = "electronics"
        st.session_state.max_budget = 50000.00
        st.session_state.last_result = None

with sc3:
    if st.button("3. Detector miss — policy blocks it", use_container_width=True):
        path = Path("data/corpus/adversarial/monitor_category_substitution_014.md")
        st.session_state.content = path.read_text(encoding="utf-8")
        st.session_state.product_id = "digital_gift_card_500"
        st.session_state.category = "gift_card"
        st.session_state.quantity = 1
        st.session_state.unit_price = 4000.00
        st.session_state.allowed_categories = "laptop"
        st.session_state.max_budget = 50000.00
        st.session_state.last_result = None

st.divider()

# -------------------------------------------------------------------------
# SECTION 2: Check Your Own Content & Inputs
# -------------------------------------------------------------------------
st.markdown("### 2. Check Your Own Content")

col_left, col_right = st.columns([1, 1], gap="large")

with col_left:
    st.markdown("#### Untrusted Content")
    st.caption("What the vendor, website, or document says.")

    uploaded_file = st.file_uploader(
        "Upload a document (TXT, Markdown, or PDF)",
        type=["txt", "md", "pdf"],
        help="Sent to FastAPI for secure document extraction.",
    )

    if uploaded_file is not None:
        # Pass document over HTTP to FastAPI
        try:
            with httpx.Client(base_url=BACKEND_URL, timeout=15.0) as client:
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                resp = client.post("/ingest-file", files=files)

            if resp.status_code == 200:
                data = resp.json()
                st.session_state.content = data["extracted_content"]
                st.success(f"Ingested '{data['filename']}' ({data['content_type']}) successfully.")
            else:
                st.error(f"This file could not be processed: {resp.text}")
        except Exception:
            st.error("Sentinel backend is unavailable. Please ensure FastAPI is running.")

    content_text = st.text_area(
        "Content being checked",
        value=st.session_state.content,
        height=200,
    )

with col_right:
    st.markdown("#### Requested Action")
    st.caption("What the agent is proposing to do.")
    r_col1, r_col2 = st.columns(2)
    with r_col1:
        prod_val = st.text_input("Product ID", value=st.session_state.product_id)
        qty_val = st.number_input("Quantity", min_value=1, value=int(st.session_state.quantity), step=1)
    with r_col2:
        cat_val = st.text_input("Category", value=st.session_state.category)
        price_val = st.number_input("Unit price (₹)", min_value=0.01, value=float(st.session_state.unit_price), step=100.0)

    st.markdown("#### User Limits")
    st.caption("What the user actually authorized (TaskScope).")
    u_col1, u_col2 = st.columns(2)
    with u_col1:
        allowed_cats = st.text_input("Allowed categories", value=st.session_state.allowed_categories)
    with u_col2:
        max_budget = st.number_input("Maximum budget (₹)", min_value=0.01, value=float(st.session_state.max_budget), step=500.0)

st.write("")
check_action_clicked = st.button("Evaluate Action with Sentinel", type="primary", use_container_width=True)

if check_action_clicked:
    allowed_list = [c.strip() for c in allowed_cats.split(",") if c.strip()]
    payload = {
        "content": content_text,
        "product_id": prod_val,
        "category": cat_val,
        "quantity": int(qty_val),
        "unit_price": float(price_val),
        "task_scope": {
            "allowed_categories": allowed_list,
            "max_budget": float(max_budget),
        },
    }

    try:
        with httpx.Client(base_url=BACKEND_URL, timeout=15.0) as client:
            resp = client.post("/scan", json=payload)
        if resp.status_code == 200:
            st.session_state.last_result = resp.json()
        else:
            st.error(f"Sentinel evaluation failed: {resp.text}")
    except Exception:
        st.error("Sentinel backend is unavailable. Please ensure FastAPI is running.")

# -------------------------------------------------------------------------
# SECTION 3: Results & Execution Status
# -------------------------------------------------------------------------
if st.session_state.last_result is not None:
    res = st.session_state.last_result
    st.divider()
    st.markdown("### 3. Sentinel Decision")

    decision = res["policy_decision"]
    executed = res["executed"]

    col_dec, col_exec = st.columns(2)
    with col_dec:
        if decision == "ALLOW":
            st.success("### ✓ ACTION ALLOWED\nThe requested purchase is within the user's limits.")
        elif decision == "REVIEW":
            st.warning("### ⚠ ACTION NEEDS REVIEW\nSentinel detected suspicious instructions in the content.")
        else:
            st.error("### ✕ ACTION BLOCKED\nThe requested action is outside the user's authorized scope.")

    with col_exec:
        if executed:
            st.success("### Was the action executed?\n# YES")
        else:
            st.error("### Was the action executed?\n# NO")

    st.write(f"**Why Sentinel decided this:** {res['policy_reason']}")

    # Compact Pipeline Trace
    st.markdown("#### Security Chain")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.caption("Content Checked")
        det_lbl = "Looks safe" if res["detector_label"] == "SAFE" else "Suspicious content detected"
        st.write(f"**{det_lbl}**")
    with c2:
        st.caption("Action Evaluated")
        st.write(f"**{prod_val}** ({cat_val})")
    with c3:
        st.caption("User Limits Checked")
        st.write(f"Scope: **{decision}**")
    with c4:
        st.caption("Execution Gate")
        st.write("**EXECUTED**" if executed else "**NOT EXECUTED**")

    # Technical Details (Collapsible)
    with st.expander("Technical details"):
        st.markdown(f"- **Correlation ID:** `{res['correlation_id']}`")
        st.markdown(f"- **Artifact Hash:** `{res['artifact_hash']}`")
        st.markdown(f"- **Inspection Route:** `{res['inspection_route']}` ({res['inspection_reason']})")
        st.markdown(f"- **Detector Classification:** `{res['detector_label']}` (score: `{res['detector_score']}`)")
        st.markdown(f"- **Policy Gate Verdict:** `{res['policy_decision']}`")
        st.markdown(f"- **Audit Event Chain:** `{' ➔ '.join(res['audit_events'])}`")
        st.markdown("##### Raw JSON Response")
        st.json(res)