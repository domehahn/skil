store = Chroma(persist_directory="./agent-memory")
store.add_documents(user_documents)
store.persist()
