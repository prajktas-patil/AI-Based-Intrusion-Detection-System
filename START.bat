@echo off
echo Starting SentinelMesh...
cd C:\Users\prajkta\Desktop\IDS

start "SentinelMesh API" cmd /k "E:\Users\prajkta\anaconda3\Scripts\uvicorn.exe api_server:app --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak

start "SentinelMesh Dashboard" cmd /k "E:\Users\prajkta\anaconda3\Scripts\streamlit.exe run dashboard.py"

timeout /t 3 /nobreak

start http://localhost:8501

echo Done! Dashboard opening in browser...
