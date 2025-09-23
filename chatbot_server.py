import os
import json
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# --- MODIFIED: Import new libraries ---
from groq import Groq
from sentence_transformers import SentenceTransformer, util

# --- 1. CONFIGURATION & SETUP ---
load_dotenv()
app = Flask(__name__)
CORS(app) 

# --- MODIFIED: Use Groq API Key ---
# Make sure you have GROQ_API_KEY in your .env file
client = Groq(
    api_key=os.environ.get("GROQ_API_KEY"),
)

# --- 2. KNOWLEDGE BASE SETUP ---
try:
    with open('data.json', 'r') as f:
        topics_data = json.load(f)
except FileNotFoundError:
    print("Error: data.json not found. Please create it.")
    topics_data = []

documents = [
    f"Class: {item['class']}, Subject: {item['subject']}, Topic: {item['topic']}" 
    for item in topics_data
]

# --- MODIFIED: Generate embeddings locally using Sentence Transformers ---
print("Loading embedding model and generating embeddings...")
# Using a popular, lightweight model for this task
embedding_model = SentenceTransformer('all-MiniLM-L6-v2') 
document_embeddings = embedding_model.encode(documents, convert_to_tensor=True)
print("Embeddings generated successfully.")


# --- 3. CORE RAG LOGIC (MODIFIED) ---
def find_best_passages(query, model, doc_embeddings, docs, top_k=3):
    """Finds the most relevant passages using Sentence Transformers."""
    query_embedding = model.encode(query, convert_to_tensor=True)
    
    # Calculate cosine similarity
    cos_scores = util.pytorch_cos_sim(query_embedding, doc_embeddings)[0]
    
    # Get the top_k scores and indices
    top_results = np.argpartition(-cos_scores, range(top_k))[0:top_k]
    
    return [docs[i] for i in top_results]

# --- 4. API ENDPOINT (MODIFIED FOR GROQ) ---
@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message', '')
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    try:
        # 1. RETRIEVAL (using the new local embedding logic)
        relevant_passages = find_best_passages(user_message, embedding_model, document_embeddings, documents)
        
        # 2. AUGMENTATION (prompt remains the same)
        prompt = f"""
        You are EduBot, a helpful assistant for the EduPlay Learning Portal.
        Your knowledge is strictly limited to the following topics.
        Do not answer questions about anything else.
        
        AVAILABLE TOPICS:
        ---
        {relevant_passages}
        ---

        Based ONLY on the topics provided, answer the user's question.
        If the question is about a topic not listed, politely say that you can only help with topics in the EduPlay portal.
        
        USER'S QUESTION: "{user_message}"
        """

        # 3. GENERATION (using the Groq API)
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant for the EduPlay Learning Portal."
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama3-8b-8192", # Using a Llama 3 model on Groq
        )
        
        bot_reply = chat_completion.choices[0].message.content
        return jsonify({"reply": bot_reply})

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"error": "Failed to generate response"}), 500

# --- RUN THE SERVER ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)