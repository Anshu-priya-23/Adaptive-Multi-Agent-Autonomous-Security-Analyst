import sys
import chromadb

if len(sys.argv) < 2:
    sys.exit(1)

ip_address = sys.argv[1]
# If Java asks for more logs (expanded search), use that limit, otherwise default to 5
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5

try:
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    collection = chroma_client.get_collection(name="network_logs")

    # Vector similarity search for the IP
    results = collection.query(
        query_texts=[ip_address],
        n_results=limit
    )

    if results and results['documents']:
        for doc in results['documents'][0]:
            print(f"EVIDENCE: {doc}")
except Exception as e:
    print(f"Error querying ChromaDB: {str(e)}")