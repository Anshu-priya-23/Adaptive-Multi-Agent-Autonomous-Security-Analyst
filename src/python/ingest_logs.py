import sys
import chromadb
import uuid

if len(sys.argv) < 2:
    print("Error: No dataset file provided.")
    sys.exit(1)

file_path = sys.argv[1]
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="network_logs")

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        # Read lines, ignoring empty ones
        logs = [line.strip() for line in f if line.strip()]
    
    if not logs:
        print("Dataset is empty.")
        sys.exit(0)

    # Generate unique IDs for vector storage
    ids = [str(uuid.uuid4()) for _ in logs]
    
    collection.add(documents=logs, ids=ids)
    print(f"SUCCESS: Indexed {len(logs)} new log entries into ChromaDB.")

except Exception as e:
    print(f"FAILED: {str(e)}")