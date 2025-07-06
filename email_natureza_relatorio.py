import openai
import json
import time
import threading
from functools import wraps
import traceback
import ast
import os

# Carregar configurações
apikey = os.environ.get('OPENAI_API_KEY')
if not apikey:
    try:
        with open("data/keys/apikeychatgpt.json", "r", encoding="utf8") as arcapikey:
            apikey = json.load(arcapikey)[0]
        print("✓ API Key carregada do arquivo")
    except Exception as e:
        print(f"❌ ERRO ao carregar API Key: {str(e)}")
        apikey = None
else:
    print("✓ API Key carregada das variáveis de ambiente")

try:
    with open("data/prompts/prompt_gpt_email.json", "r", encoding="utf8") as arcpromtgpt:
        promtchatgpt = json.load(arcpromtgpt)[0]
    print("✓ Prompt carregado com sucesso")
except Exception as e:
    print(f"❌ ERRO ao carregar prompt: {str(e)}")
    promtchatgpt = "Analise este email e classifique como confiável, suspeito, desconhecido ou malicioso."

# SISTEMA DE CIRCUIT BREAKER PARA API OPENAI
class OpenAICircuitBreaker:
    def __init__(self):
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.failure_threshold = 3
        self.recovery_timeout = 120  # 2 minutos
        self.lock = threading.Lock()
    
    def call_api(self, func, *args, **kwargs):
        with self.lock:
            if self.state == 'OPEN':
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = 'HALF_OPEN'
                    print("🔄 Circuit Breaker: Tentando recuperação da API OpenAI")
                else:
                    raise Exception("API OpenAI temporariamente indisponível (Circuit Breaker OPEN)")
        
        try:
            result = func(*args, **kwargs)
            with self.lock:
                if self.state == 'HALF_OPEN':
                    self.state = 'CLOSED'
                    self.failure_count = 0
                    print("✅ Circuit Breaker: API OpenAI recuperada")
            return result
        except Exception as e:
            with self.lock:
                self.failure_count += 1
                self.last_failure_time = time.time()
                
                if self.failure_count >= self.failure_threshold:
                    self.state = 'OPEN'
                    print(f"🚨 Circuit Breaker: API OpenAI ABERTA após {self.failure_count} falhas")
            
            raise e

# Instância global do circuit breaker
openai_circuit_breaker = OpenAICircuitBreaker()

# SISTEMA DE RETRY COM BACKOFF EXPONENCIAL
def retry_with_backoff(max_retries=2, base_delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt == max_retries:
                        print(f"❌ Máximo de tentativas atingido: {str(e)}")
                        raise last_exception
                    
                    delay = base_delay * (2 ** attempt)
                    print(f"🔄 Tentativa {attempt + 1}/{max_retries + 1}, aguardando {delay}s")
                    time.sleep(delay)
            
            raise last_exception
        return wrapper
    return decorator

# SISTEMA DE TIMEOUT PARA OPERAÇÕES
def with_timeout(seconds=25):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = [None]
            exception = [None]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(seconds)
            
            if thread.is_alive():
                print(f"⏰ Timeout atingido ({seconds}s)")
                raise TimeoutError(f"Operação excedeu {seconds} segundos")
            
            if exception[0]:
                raise exception[0]
            
            return result[0]
        return wrapper
    return decorator

# FUNÇÃO PRINCIPAL DE ANÁLISE - COMPLETAMENTE PROTEGIDA
@retry_with_backoff(max_retries=2, base_delay=1)
@with_timeout(seconds=25)
def call_openai_api(email_content):
    """Chamada protegida para API OpenAI"""
    if not apikey:
        raise Exception("API Key não disponível")
    
    client = openai.OpenAI(api_key=apikey)
    
    # Limitar tamanho do conteúdo para evitar timeouts
    max_content_length = 8000  # Reduzido para maior estabilidade
    if len(email_content) > max_content_length:
        email_content = email_content[:max_content_length] + "... [conteúdo truncado]"
    
    response = client.chat.completions.create(
        model="gpt-4.1-mini",  # Modelo mais rápido e estável
        messages=[
            {
                "role": "system",
                "content": promtchatgpt
            },
            {
                "role": "user", 
                "content": f"Analise este email: {email_content}"
            }
        ],
        temperature=0,
        max_tokens=800,  # Reduzido para resposta mais rápida
        top_p=1,
        stream=False,
        timeout=20  # Timeout explícito da API
    )
    
    print(f"✓ Tokens usados: {response.usage.total_tokens}")
    return response.choices[0].message.content

# DEFINIR FUNCAO DE ANALISE GPT - OTIMIZADA COM LOGS DETALHADOS
def apichatgptemail(email):
    print("🔍 === INÍCIO ANÁLISE EMAIL ===")
    print(f"📧 Tamanho do email: {len(email)} caracteres")
    print(f"📧 Primeiros 100 chars: {email[:100]}...")
        
    # DEFININDO PARÂMETROS QUE ENVIO DO PYTHON DA API PARA O ARQUIVO PYTHON FLASK PARA O HTML
    clas='Filtros Pendentes'
    domi='Aqui forneceremos dados a respeito da notabilidade do autor do email'
    just='Aqui reportaremos informações sobre o julgamento do conteúdo geral do email'
    segu='Aqui recomendaremos medidas de segurança gerais'
    corl="#58697a"

    print("🔑 Verificando API Key...")
    if not apikey:
        print("❌ API Key não disponível!")
        return [clas, domi, just, segu, ['0'], corl]

    print("🤖 Iniciando cliente OpenAI...")
    client = openai.OpenAI(api_key=f"{apikey}")

    # Função para tentar análise com retry
    def tentar_analise(tentativa=1, max_tentativas=2):
        try:
            print(f"📤 Tentativa {tentativa}/{max_tentativas} - Enviando requisição para OpenAI...")
            print(f"📋 Prompt: {promtchatgpt[:100]}...")
            
            # Limitar tamanho do email para evitar timeouts
            email_limited = email[:6000] if len(email) > 6000 else email
            if len(email) > 6000:
                print(f"⚠️ Email truncado de {len(email)} para {len(email_limited)} caracteres")
            
            response = client.chat.completions.create(
                model="gpt-4o-mini",  # Modelo mais rápido e barato
                messages=[
                    {
                        "role": "system",
                        "content": promtchatgpt
                    },
                    {
                        "role": "user", 
                        "content": f"Analise este email: {email_limited}"
                    }
                ],
                temperature=0,
                max_tokens=800,  # Reduzido de 1000 para 500 (suficiente para resposta)
                top_p=1,
                stream=False  # Desabilitar streaming para resposta mais rápida
            )
            
            print(f"✅ Resposta recebida da OpenAI!")
            print(f"📊 Tokens usados: {response.usage.total_tokens}")
            
            # Processar resposta
            resposta_completa = response.choices[0].message.content
            print(f"📝 Resposta completa: {resposta_completa}")
            
            # Verificar se a resposta é válida
            if resposta_completa.strip() == "0" or len(resposta_completa.strip()) < 10:
                print(f"⚠️ Resposta inválida (tentativa {tentativa}): '{resposta_completa}'")
                if tentativa < max_tentativas:
                    print(f"🔄 Tentando novamente...")
                    return tentar_analise(tentativa + 1, max_tentativas)
                else:
                    print("❌ Máximo de tentativas atingido, usando resposta padrão")
                    return None
            
            # Converter a resposta para dicionário Python
            try:
                resposta_dict = ast.literal_eval(resposta_completa)
            except (ValueError, SyntaxError):
                # Se houver texto extra fora do dicionário, tenta extrair somente a parte entre chaves
                inicio = resposta_completa.find('{')
                fim = resposta_completa.rfind('}') + 1
                if inicio != -1 and fim != -1:
                    try:
                        resposta_dict = ast.literal_eval(resposta_completa[inicio:fim])
                    except Exception:
                        resposta_dict = {}
                else:
                    resposta_dict = {}

            # Verifica se as chaves esperadas estão presentes
            if isinstance(resposta_dict, dict) and 'classificacao' in resposta_dict:
                print("✅ Resposta válida em formato de dicionário!")
                return resposta_dict
            else:
                print("⚠️ Resposta em formato inesperado")
                if tentativa < max_tentativas:
                    print(f"🔄 Tentando novamente...")
                    return tentar_analise(tentativa + 1, max_tentativas)
                else:
                    print("❌ Máximo de tentativas atingido, usando resposta padrão")
                    return None
                    
        except Exception as e:
            print(f"❌ Erro na tentativa {tentativa}: {str(e)}")
            if tentativa < max_tentativas:
                print(f"🔄 Tentando novamente...")
                return tentar_analise(tentativa + 1, max_tentativas)
            else:
                print("❌ Máximo de tentativas atingido")
                raise e

    # OTIMIZAÇÃO: Usar modelo mais leve e eficiente
    try:
        # Tentar análise com retry
        resposta_dict = tentar_analise()
        
        if isinstance(resposta_dict, dict) and 'classificacao' in resposta_dict:
            print("✅ Processando resposta válida em dicionário...")
            clas = resposta_dict.get('classificacao', clas).replace('\\n', '').replace("'", '').lower()
            domi = resposta_dict.get('remetente', domi).replace('\\n', '')
            just = resposta_dict.get('conteudo', just).replace('\\n', '')
            segu = resposta_dict.get('seguranca', segu).replace('\\n', '').replace("'", '')
            print(f"🎯 Classificação: {clas}")
            print(f"🌐 Domínio: {domi[:50]}...")
            print(f"📋 Justificativa: {just[:50]}...")
            print(f"🔒 Segurança: {segu[:50]}...")
        else:
            print("⚠️ Usando valores padrão devido a resposta inválida")
            clas = 'Tente Novamente'
            domi = 'Aqui forneceremos dados a respeito da notabilidade do autor do email'
            just = 'Aqui reportaremos informações sobre o julgamento do conteúdo geral do email'
            segu = 'Aqui recomendaremos medidas de segurança gerais'
            corl = "#58697a"
        
        # DEFINIR CORES PARA COLOCAR NO FUNDO DO RETÂNGULO
        print("🎨 Definindo cor baseada na classificação...")
        if "confiável" in clas:
            corl = "#27772e"
            print("✅ Cor: Verde (Confiável)")
        elif "malicioso" in clas:
            corl = "#961616"
            print("❌ Cor: Vermelho (Malicioso)")
        elif "suspeito" in clas:
            corl = "#8d3d7c"
            print("⚠️ Cor: Roxo (Suspeito)")
        elif "desconhecido" in clas:
            corl = "#733179"
            print("🟣 Cor: Roxo (Desconhecido)")
        elif corl == "#58697a":
            corl = "#58697a"
            print("🔵 Cor: Azul (Padrão)")
        else:
            corl = "#733179"
            print("🟣 Cor: Roxo (Outro)")
        
        # RETORNAR CLASSIFICAÇÃO, DOMINIO, JUSTIFICATIVA, SEGURANÇA, LISTA DE ITENS DO OUTPUT SEPARADO, COR
        resultado = [clas, domi, just, segu, resposta_dict if isinstance(resposta_dict, dict) else {'0': 0}, corl]
        print(f"✅ ANÁLISE CONCLUÍDA: {clas}")
        print("🔍 === FIM ANÁLISE EMAIL ===")
        return resultado
        
    except Exception as e:
        print(f"❌ ERRO na análise: {str(e)}")
        print(f"📋 Traceback: {traceback.format_exc()}")
        # Fallback para resposta padrão em caso de erro
        print("🔄 Retornando resposta de erro padrão")
        return ['Erro na Análise', 'Erro ao processar análise', 'Tente novamente mais tarde', 'Verifique sua conexão', ['0'], "#58697a"]

# Função de teste para verificar se tudo está funcionando
def test_api_connection():
    """Testa a conexão com a API OpenAI"""
    try:
        if not apikey:
            return False, "API Key não disponível"
        
        client = openai.OpenAI(api_key=apikey)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Teste"}],
            max_tokens=10
        )
        return True, "API funcionando"
    except Exception as e:
        return False, f"Erro na API: {str(e)}"

if __name__ == "__main__":
    # Teste da API
    success, message = test_api_connection()
    print(f"Teste da API: {message}")
