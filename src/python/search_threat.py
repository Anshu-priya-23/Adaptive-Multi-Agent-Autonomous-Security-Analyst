import chromadb
import sys
import os

def search_logs(ip_address):
    # 1. Connect to the Vector Database
    db_path = os.path.join(os.path.dirname(__file__), "..", "..", "chroma_db")
    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_collection(name="security_logs")
    
    # 2. Perform the semantic search for the IP address
    results = collection.query(
        query_texts=[ip_address],
        n_results=2 # Retrieve the top 2 closest matches
    )
    
    # 3. Output the findings so Java can read them later
    print(f"--- RAG Search Results for {ip_address} ---")
    if results['documents'] and len(results['documents'][0]) > 0:
        for doc in results['documents'][0]:
            print(f"EVIDENCE: {doc}")
    else:
        print("No historical anomalies found for this IP.")

if __name__ == "__main__":
    # This allows us to pass the IP address from the terminal (or from Java!)
    if len(sys.argv) < 2:
        print("Error: Please provide an IP address.")
    else:
        target_ip = sys.argv[1]
        search_logs(target_ip)