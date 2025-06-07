import streamlit as st
import re
import json
import ast
from uuid import uuid4
from pymongo import MongoClient
from urllib.parse import quote_plus
from bson import ObjectId
from google import genai
from huggingface_hub import InferenceClient

# --- Hugging Face InferenceClient ---
HF_TOKEN = "hf_your_real_token"  # 🔐 Thay bằng token thật
HF_MODEL = "droidriz/FineLlama-3.2-3B-PII-Tool"
hf_client = InferenceClient(model=HF_MODEL, token=HF_TOKEN)

# --- Hàm xử lý Hugging Face qua InferenceClient ---
def get_response_from_api(user_message):
    messages = {
        "messages": [
            {
                "role": "system",
                "content": "You are an expert model trained to redact potentially sensitive information from documents..."
            },
            {
                "role": "user",
                "content": user_message,
            }
        ],
        "tools": [{
            "function": {
                "name": "redact",
                "description": "Extract PII",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fields_to_redact": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["string", "pii_type"],
                                "properties": {
                                    "string": {"type": "string"},
                                    "pii_type": {"type": "string"},
                                },
                            },
                        }
                    },
                },
            },
            "type": "function",
        }],
        "tool_choice": {"type": "function", "function": {"name": "redact"}},
    }

    prompt = {
        "inputs": messages,
        "parameters": {
            "max_new_tokens": 4096,
            "temperature": 0.0
        }
    }

    response = hf_client.text_generation(json.dumps(prompt), max_new_tokens=1024)
    return response

# --- Các hàm xử lý nội dung ---
def extract_content(text):
    match = re.search(r"<\|start_header_id\|>assistant<\|end_header_id\|>(.*?)<\|eot_id\|>", text, re.DOTALL)
    return match.group(1).strip() if match else ""

def postprocess_tool_response_v2(raw_response):
    try:
        outer_dict = ast.literal_eval(raw_response.replace('(TOOL)', '').strip())
        args = json.loads(outer_dict.get("arguments", "{}"))
        return {"redact": args.get("fields_to_redact", [])}
    except:
        return {"redact": []}

def build_masked_input_and_mapping(user_msg, pii_fields):
    masked_input = user_msg
    mapping = {}
    for field in pii_fields:
        original = field["string"]
        pii_type = field["pii_type"]
        mask = f"[PII_{pii_type}_{str(uuid4())[:8]}]"
        mapping[mask] = original
        masked_input = masked_input.replace(original, mask)
    return masked_input, mapping

def unmask_llm_response(llm_response, mapping):
    for mask, val in mapping.items():
        llm_response = llm_response.replace(mask, val)
    return llm_response

# --- MongoDB ---
def save_mapping_to_mongo(mapping):
    password = quote_plus("8v1t1n8F7D06hlYG")
    uri = f"mongodb+srv://vothiennhanhcmut:{password}@cluster0.xw9k26q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = MongoClient(uri)
    col = client["PII_masking"]["PII"]
    return col.insert_one({"pii_mapping": mapping}).inserted_id

def get_mapping_from_mongo(object_id):
    password = quote_plus("8v1t1n8F7D06hlYG")
    uri = f"mongodb+srv://vothiennhanhcmut:{password}@cluster0.xw9k26q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = MongoClient(uri)
    doc = client["PII_masking"]["PII"].find_one({"_id": ObjectId(object_id)})
    return doc["pii_mapping"]

# --- Gemini ---
def get_gemini_response(masked_input):
    genai_client = genai.Client(api_key="AIzaSyDrYywkd0rdaVq4JL-iZax7_oOuqpLRiVA")
    prompt = f"make a formal invitation to the following person existing in the below information, do not change any value:\n{masked_input}"
    return genai_client.models.generate_content(model="gemini-2.0-flash", contents=prompt).text

# --- Streamlit App ---
st.set_page_config(page_title="🔐 PII Redaction App", layout="centered")
st.title("🔐 Generate Formal Invitation with PII Redaction")

user_msg = st.text_area("✍️ Nhập nội dung có thể chứa thông tin nhạy cảm (PII):", height=200)

if st.button("🚀 Xử lý"):
    with st.spinner("🧠 Đang gọi Hugging Face model..."):
        raw_response = get_response_from_api(user_msg)
        ft_response = extract_content(raw_response)
        pii_info = postprocess_tool_response_v2(ft_response)
        masked_input, mapping = build_masked_input_and_mapping(user_msg, pii_info["redact"])
        doc_id = save_mapping_to_mongo(mapping)

    st.success("✅ Đã phát hiện và che thông tin PII")
    st.subheader("🧱 Masked Input")
    st.code(masked_input)

    with st.spinner("✉️ Đang tạo thư mời với Gemini..."):
        llm_output = get_gemini_response(masked_input)
        final_output = unmask_llm_response(llm_output, mapping)

    st.subheader("📨 Kết quả cuối cùng (Đã khôi phục)")
    st.write(final_output)
