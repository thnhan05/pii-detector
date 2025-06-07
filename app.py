# app.py
import streamlit as st
from uuid import uuid4
import json
import re
import requests
import ast
import pymongo
from pymongo import MongoClient
from urllib.parse import quote_plus
from bson import ObjectId
from google import genai

# Config Hugging Face
API_URL = "https://api-inference.huggingface.co/models/droidriz/FineLlama-3.2-3B-PII-Tool"
API_TOKEN = "hf_your_token_here"
headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json",
}

# Hugging Face API call
def get_response_from_api(user_message):
    test_message = {
        "messages": [
            {
                "role": "system",
                "content": "You are an expert model trained to redact potentially sensitive information from documents..."
            },
            {
                "role": "user",
                "content": user_message,
            },
        ],
        "tools": [{
            "function": {
                "name": "redact",
                "description": "Extract PII data from text",
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
            "type": "function"
        }],
        "tool_choice": {"type": "function", "function": {"name": "redact"}}
    }
    payload = {
        "inputs": test_message,
        "parameters": {"max_new_tokens": 4096, "temperature": 0.0}
    }
    response = requests.post(API_URL, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()[0].get("generated_text", "")

# Extract and process
def extract_content(text):
    match = re.search(r"<\|start_header_id\|>assistant<\|end_header_id\|>(.*?)<\|eot_id\|>", text, re.DOTALL)
    return match.group(1).strip() if match else None

def postprocess_tool_response_v2(raw_response):
    try:
        outer_dict = ast.literal_eval(raw_response.replace('(TOOL)', '').strip())
        args = json.loads(outer_dict.get("arguments", "{}"))
        return {"redact": args.get("fields_to_redact", [])}
    except Exception:
        return {"redact": []}

def build_masked_input_and_mapping(user_msg, pii_fields):
    masked_input = user_msg
    mapping = {}
    for field in pii_fields:
        original = field["string"]
        pii_type = field["pii_type"]
        mask_id = f"[PII_{pii_type}_{str(uuid4())[:8]}]"
        mapping[mask_id] = original
        masked_input = masked_input.replace(original, mask_id)
    return masked_input, mapping

def unmask_llm_response(llm_response, pii_mapping):
    for mask, real_value in pii_mapping.items():
        llm_response = llm_response.replace(mask, real_value)
    return llm_response

# MongoDB
def save_to_mongo(mapping):
    password = quote_plus("8v1t1n8F7D06hlYG")
    uri = f"mongodb+srv://vothiennhanhcmut:{password}@cluster0.xw9k26q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = MongoClient(uri)
    mycol = client["PII_masking"]["PII"]
    return mycol.insert_one({"pii_mapping": mapping}).inserted_id

def get_mapping_from_mongo(doc_id):
    password = quote_plus("8v1t1n8F7D06hlYG")
    uri = f"mongodb+srv://vothiennhanhcmut:{password}@cluster0.xw9k26q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = MongoClient(uri)
    return client["PII_masking"]["PII"].find_one({"_id": ObjectId(doc_id)})["pii_mapping"]

# Gemini output
def get_gemini_response(prompt):
    genai_client = genai.Client(api_key="AIzaSyDrYywkd0rdaVq4JL-iZax7_oOuqpLRiVA")
    response = genai_client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
    return response.text

# --- Streamlit App ---
st.set_page_config(page_title="PII Redaction App")
st.title("🔒 PII Detection and Redacted Invitation Generator")

user_msg = st.text_area("✍️ Enter the message with potential PII", height=200)

if st.button("🚀 Process"):
    with st.spinner("🔍 Detecting PII..."):
        raw_response = get_response_from_api(user_msg)
        ft_response = extract_content(raw_response)
        result = postprocess_tool_response_v2(ft_response)
        pii_fields = result["redact"]
        masked_input, mapping = build_masked_input_and_mapping(user_msg, pii_fields)
        mongo_id = save_to_mongo(mapping)

    st.success("✅ PII detected and masked!")

    st.subheader("🔐 Masked Message")
    st.code(masked_input)

    with st.spinner("✉️ Generating formal invitation..."):
        prompt = f"make a formal invitation to the following person existing in the below information, do not change any value:\n{masked_input}"
        llm_response = get_gemini_response(prompt)
        final_response = unmask_llm_response(llm_response, mapping)

    st.subheader("📨 Final Response (Unmasked)")
    st.write(final_response)
