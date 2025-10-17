#1차 스켈레톤 코드

import asyncio
import aiohttp # pip로 설치해야 사용가능.
from typing import Dict, Any, List

class CalderaClient: 
    def __init__(self, base_url: str, api_key: str = None):
        
        self.base_url = base_url.rstrip('/')
        self.headers = {'KEY': api_key} if api_key else {}
        self.session = None

    async def _ensure_session(self):
        if self.session is None or self.session.closed:
            connector = aiohttp.TCPConnector(ssl=False) 
            self.session = aiohttp.ClientSession(headers=self.headers, connector=connector)
        
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def get_operation_by_id(self, op_id: str) -> Dict[str, Any]:
        await self._ensure_session()
        url = f"{self.base_url}/api/rest" 
        
        payload = {
            "index": "operations", 
            "id": op_id
        }
        
        try:
            async with self.session.post(url, json=payload) as response:
                response.raise_for_status()
                data = await response.json()
                return data[0] if isinstance(data, list) and data else {}
        except Exception as e:
            print(f"Error fetching operation {op_id}: {e}")
            return {}

    def extract_detection_context(self, operation_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        context = []
        execution_chain = operation_data.get('chain', [])

        for link in execution_chain:
            ability = getattr(link, 'ability', {})
            
            technique_id = ability.get('technique_id') if isinstance(ability, dict) else None
            ability_name = ability.get('name') if isinstance(ability, dict) else 'N/A'
            
            timestamp = getattr(link, 'finish', None) or getattr(link, 'start', None) or getattr(link, 'decide', None)
            
            command_executed = getattr(link, 'command', 'Unknown Command')
            
            if technique_id:
                context.append({
                    'technique_id': technique_id,
                    'ability_name': ability_name,
                    'executed_at_iso': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else timestamp,
                    'raw_command_ioc': command_executed
                })
        
        return context

async def main():
    client = CalderaClient(base_url="http://127.0.0.1:8888") 
    
    op_id = "1" 
    
    op_data = await client.get_operation_by_id(op_id)
    
    if op_data:
        context = client.extract_detection_context(op_data)
        print(f"--- Operation {op_id} Context ---")
        for item in context:
            print(item)
    
    await client.close()

# if __name__ == '__main__':
#     asyncio.run(main())
