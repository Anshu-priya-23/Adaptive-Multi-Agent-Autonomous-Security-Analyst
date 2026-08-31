import chromadb
import os

def init_vector_db():
    # Define where the database will be saved
    db_path = os.path.join(os.path.dirname(__file__), "..", "..", "chroma_db")
    
    # Initialize the PersistentClient
    client = chromadb.PersistentClient(path=db_path)
    
    # Create a collection (table) for the logs
    collection = client.get_or_create_collection(name="security_logs")
    
    print(f"Success! Vector DB initialized at: {db_path}")
    print(f"Collection '{collection.name}' is ready for data.")

if __name__ == "__main__":
    init_vector_db()