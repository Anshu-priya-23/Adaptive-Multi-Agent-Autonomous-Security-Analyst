import chromadb
import sys
import os

def search_logs(ip_address):
    # Connect to the Vector Database
    db_path = os.path.join(os.path.dirname(__file__), "..", "..", "chroma_db")
    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_collection(name="security_logs")
    
    # Retrieve historical evidence
    results = collection.query(
        query_texts=[ip_address],
        n_results=2
    )
    
    if results['documents'] and len(results['documents'][0]) > 0:
        for doc in results['documents'][0]:
            print(f"EVIDENCE: {doc}")
    else:
        print("No historical data found for this IP.")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        search_logs(sys.argv[1])