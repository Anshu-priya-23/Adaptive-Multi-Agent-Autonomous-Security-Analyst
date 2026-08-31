import chromadb
import pandas as pd
import os
import uuid

def ingest_data():
    # 1. Connect to our existing Vector Database
    db_path = os.path.join(os.path.dirname(__file__), "..", "..", "chroma_db")
    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_collection(name="security_logs")
    
    # 2. Read the sample CSV file
    csv_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "sample_network_logs.csv")
    df = pd.read_csv(csv_path)
    
    # 3. Process and insert each row into the database
    for index, row in df.iterrows():
        # Convert the row into a readable sentence for the AI
        log_text = f"Time: {row['Timestamp']} | Src IP: {row['Source IP']} | Dest IP: {row['Destination IP']} | Port: {row['Destination Port']} | Action: {row['Activity']}"
        
        # Insert into ChromaDB (Chroma handles the embedding automatically!)
        collection.add(
            documents=[log_text],
            metadatas=[{"source": "network_log", "ip": row['Source IP']}],
            ids=[str(uuid.uuid4())]
        )
        
    print(f"Success! {len(df)} logs were ingested into the RAG database.")

if __name__ == "__main__":
    ingest_data()