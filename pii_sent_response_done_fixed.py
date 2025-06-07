# In[ ]: Check if running in Colab
import os

if "COLAB_" not in "".join(os.environ.keys()):
    pass
else:
    pass

# In[ ]: Load the finetuned model
from unsloth import FastLanguageModel
import torch

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="droidriz/FineLlama-3.2-3B-PII-Tool",
    max_seq_length=1024,
    load_in_4bit=True,
    load_in_8bit=False,
    full_finetuning=False,
)

# In[ ]: Function to extract content
import re

def extract_content(text):
    pattern = r"<\|start_header_id\|>assistant<\|end_header_id\|>(.*?)<\|eot_id\|>"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None

# In[ ]: Load utils
import sys
sys.path.append('/kaggle/input/utils-data')
from utils import get_tools_prefix_messages

# In[ ]: Function to get response from finetuned model
from litserve.specs.openai import Tool, ChatMessage

def get_response_from_finetuned_model(model, tokenizer_ft, user_message):
    test_message = {
        "messages": [
            {
                "role": "system",
                "content": "You are an expert model trained to redact potentially sensitive information from documents. You have been given a document to redact. Your goal is to accurately redact the sensitive information from the document...",
            },
            {
                "role": "user",
                "content": user_message,
            },
        ],
        "tools": [
            {
                "function": {
                    "name": "redact",
                    "description": "To Extract the Personally Identifiable Information data from the given text by user.",
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
            }
        ],
        "tool_choice": {
            "type": "function",
            "function": {
                "name": "redact"
            }
        }
    }

    tools_json = test_message['tools']
    tools = [Tool.model_validate(tool) for tool in tools_json]
    messages = [ChatMessage.model_validate(m) for m in test_message['messages']]
    messages = get_tools_prefix_messages(messages, tools)
    messages_json = [m.model_dump(exclude_none=True) for m in messages]

    model_inputs_new = tokenizer_ft.apply_chat_template(
        messages_json,
        tokenize=True,
        add_generation_prompt=True,
        return_tensors="pt"
    ).to(model.device)

    outputs = model.generate(input_ids=model_inputs_new, max_new_tokens=4096, use_cache=True)
    response = tokenizer.batch_decode(outputs)[0]
    return extract_content(response)

# In[ ]: User message
user_msg = "Please contact Dr. Amanda Rodriguez at amanda.rodriguez@example.com or call her at 1 TWO 3-four567 regarding account #AC-78593201."

# In[ ]: Run finetuned model
ft_response = get_response_from_finetuned_model(model, tokenizer, user_msg)

# In[ ]: Post-process response
import ast
import json

def postprocess_tool_response_v2(raw_response):
    clean_text = raw_response.replace('(TOOL)', '').strip()
    try:
        outer_dict = ast.literal_eval(clean_text)
        if 'arguments' in outer_dict:
            arguments_str = outer_dict['arguments']
            arguments_json = json.loads(arguments_str)
            return {"redact": arguments_json.get("fields_to_redact", [])}
        else:
            return {"redact": []}
    except Exception as e:
        print("Error in postprocess_tool_response_v2:", e)
        return {"redact": []}

result = postprocess_tool_response_v2(ft_response)
print("PII fields to redact:", result["redact"])

# In[ ]: Build masked input and mapping
from uuid import uuid4

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

masked_input, mapping = build_masked_input_and_mapping(user_msg, result["redact"])
print("Masked input:\n", masked_input)
print("Mapping:\n", mapping)

# In[ ]: Connect to MongoDB
import pymongo
from pymongo import MongoClient
from urllib.parse import quote_plus

password = quote_plus("8v1t1n8F7D06hlYG")
uri = f"mongodb+srv://vothiennhanhcmut:{password}@cluster0.xw9k26q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
try:
    client.admin.command('ping')
    print("✅ Connected to MongoDB!")
except Exception as e:
    print(e)

mydb = client["PII_masking"]
mycol = mydb["PII"]
doc = {"pii_mapping": mapping}
result_mongo = mycol.insert_one(doc)
print("✅ Mapping saved to MongoDB! ObjectID:", result_mongo.inserted_id)

# In[ ]: Use Gemini API to generate final output
from google import genai
genai_client = genai.Client(api_key="AIzaSyDrYywkd0rdaVq4JL-iZax7_oOuqpLRiVA")

prompt = f"make a formal invitation to the following person existing in the below information, do not change any value:\n{masked_input}"

response = genai_client.models.generate_content(
    model="gemini-2.0-flash",
    contents=prompt
)
llm_response = response.text
print("LLM Response:\n", llm_response)

# In[ ]: Unmask final response
def unmask_llm_response(llm_response: str, pii_mapping: dict) -> str:
    for mask, real_value in pii_mapping.items():
        llm_response = llm_response.replace(mask, real_value)
    return llm_response

# Fetch mapping from MongoDB
from bson import ObjectId
doc_from_db = mycol.find_one({"_id": ObjectId(result_mongo.inserted_id)})
pii_mapping = doc_from_db["pii_mapping"]

final_response = unmask_llm_response(llm_response, pii_mapping)
print("Final Response:\n", final_response)
