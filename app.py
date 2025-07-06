from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import secrets
from datetime import timedelta, datetime
import json
import os
import traceback
import time
import threading
import queue
from functools import wraps
import signal
import sys
from config import ENV, OAUTHLIB_INSECURE_TRANSPORT
import os
import random
from flask_session import Session
from redis import Redis

if OAUTHLIB_INSECURE_TRANSPORT:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Importações condicionais para email
try:
    from email_innit import (
        iniciar_flow_oauth, finalizar_oauth, buscar_emails, remetentes, data, 
        criar_servico_gmail, buscar_emails_por_categoria, obter_categorias_disponiveis,
        EMAIL_CATEGORIES, extrair_conteudo_email
    )
    EMAIL_INNIT_AVAILABLE = True
except ImportError as e:
    print(f"AVISO: email_innit não disponível: {e}")
    EMAIL_INNIT_AVAILABLE = False

try:
    from email_natureza_relatorio import apichatgptemail
    EMAIL_RELATORIO_AVAILABLE = True
except ImportError as e:
    print(f"AVISO: email_natureza_relatorio não disponível: {e}")
    EMAIL_RELATORIO_AVAILABLE = False

# Importações para análise de site
try:
    from site_natureza_relatorio import apichatgptsite
    SITE_ANALISE_SITE_AVAILABLE = True
    SITE_RELATORIO_AVAILABLE = True  # Mantido para compatibilidade
except ImportError as e:
    print(f"AVISO: site_natureza_relatorio não disponível: {e}")
    SITE_ANALISE_SITE_AVAILABLE = False
    SITE_RELATORIO_AVAILABLE = False

# Load app secret key
secretkeyapp = os.environ.get('FLASK_SECRET_KEY', 'fallback-secret-key')
if secretkeyapp == 'fallback-secret-key':
    try:
        with open("data/keys/appkey.json", "r", encoding="utf8") as arcapikey:
            secretkeyapp = json.load(arcapikey)[0]
        print("✓ Chave da aplicação carregada do arquivo")
    except Exception as e:
        print(f"ERRO ao carregar chave: {str(e)}")
        secretkeyapp = "fallback-secret-key"
else:
    print("✓ Chave da aplicação carregada das variáveis de ambiente")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = f'{secretkeyapp}'

# Session configuration for production
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Configuração do Flask-Session para sessões server-side
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = Redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379'))
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutos

Session(app)

print("✓ Flask app inicializado")

# CACHE SERVIDOR OTIMIZADO (NÃO NA SESSÃO)
analysis_cache = {}

# SISTEMA DE CIRCUIT BREAKER PARA ELIMINAR ERROS 500/502
class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60, expected_exception=Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        
    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)
        return wrapper
    
    def call(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = 'HALF_OPEN'
                log_otimizado(f"🔄 Circuit Breaker: Tentando recuperação para {func.__name__}", 'info')
            else:
                raise Exception(f"Circuit Breaker OPEN para {func.__name__}")
        
        try:
            result = func(*args, **kwargs)
            if self.state == 'HALF_OPEN':
                self.state = 'CLOSED'
                self.failure_count = 0
                log_otimizado(f"✅ Circuit Breaker: Recuperado para {func.__name__}", 'info')
            return result
        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = 'OPEN'
                log_otimizado(f"🚨 Circuit Breaker: ABERTO para {func.__name__} após {self.failure_count} falhas", 'error', forcar=True)
            
            raise e

# SISTEMA DE RETRY COM BACKOFF EXPONENCIAL
def retry_with_backoff(max_retries=3, base_delay=1, max_delay=60):
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
                        log_otimizado(f"❌ Máximo de tentativas atingido para {func.__name__}: {str(e)}", 'error', forcar=True)
                        raise last_exception
                    
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    log_otimizado(f"🔄 Tentativa {attempt + 1}/{max_retries + 1} para {func.__name__}, aguardando {delay}s", 'warning')
                    time.sleep(delay)
            
            raise last_exception
        return wrapper
    return decorator

# SISTEMA DE TIMEOUT PARA OPERAÇÕES
def timeout_handler(signum, frame):
    raise TimeoutError("Operação excedeu o tempo limite")

def with_timeout(seconds=30):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if os.name == 'nt':  # Windows
                # Para Windows, usamos threading com timeout
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
                    log_otimizado(f"⏰ Timeout atingido para {func.__name__} ({seconds}s)", 'error', forcar=True)
                    raise TimeoutError(f"Operação {func.__name__} excedeu {seconds} segundos")
                
                if exception[0]:
                    raise exception[0]
                
                return result[0]
            else:
                # Para Unix/Linux, usamos signal
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(seconds)
                try:
                    result = func(*args, **kwargs)
                    signal.alarm(0)
                    return result
                finally:
                    signal.signal(signal.SIGALRM, old_handler)
        
        return wrapper
    return decorator

# MONITORAMENTO DE SAÚDE DO SISTEMA
class SystemHealthMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        self.last_health_check = time.time()
        self.memory_usage = 0
        self.cache_size = 0
        
    def record_request(self, success=True):
        self.request_count += 1
        if not success:
            self.error_count += 1
    
    def get_health_status(self):
        uptime = time.time() - self.start_time
        error_rate = (self.error_count / max(self.request_count, 1)) * 100
        
        return {
            'uptime_seconds': uptime,
            'total_requests': self.request_count,
            'error_count': self.error_count,
            'error_rate_percent': error_rate,
            'memory_usage_mb': self.memory_usage,
            'cache_size': self.cache_size,
            'status': 'healthy' if error_rate < 5 else 'degraded' if error_rate < 20 else 'critical'
        }

# Instância global do monitor
health_monitor = SystemHealthMonitor()

# Configuração de logs otimizada
DEBUG_MODE = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG') == 'true'

def log_otimizado(mensagem, nivel='info', forcar=False):
    """
    Sistema de logs otimizado - reduz logs em produção
    """
    if DEBUG_MODE or forcar:
        print(f"[{nivel.upper()}] {mensagem}")

def get_user_cache_key():
    """Gera chave única para cache do usuário atual"""
    try:
        oauth_credentials = session.get('oauth_credentials', {})
        user_id = oauth_credentials.get('client_id', 'anonymous')
        # Adiciona timestamp por hora para melhor isolamento
        return f"user_{user_id}_{datetime.now().strftime('%Y%m%d%H')}"
    except Exception as e:
        log_otimizado(f"Erro ao gerar chave de cache: {str(e)}", 'error', forcar=True)
        return f"user_anonymous_{datetime.now().strftime('%Y%m%d%H')}"

def verificar_propriedade_emails(emails):
    """Verifica se os emails pertencem ao usuário atual"""
    try:
        current_user_id = session.get('oauth_credentials', {}).get('client_id', 'anonymous')
        emails_verificados = []
        
        for email in emails:
            # Verifica se o email tem dados de propriedade
            if 'user_id' in email:
                if email['user_id'] == current_user_id:
                    emails_verificados.append(email)
                else:
                    log_otimizado(f"⚠️ Email de outro usuário detectado: {email.get('id', 'unknown')}", 'warning', forcar=True)
            else:
                # Se não tem user_id, assume que é do usuário atual (emails do cache)
                emails_verificados.append(email)
        
        return emails_verificados
    except Exception as e:
        log_otimizado(f"Erro ao verificar propriedade dos emails: {str(e)}", 'error', forcar=True)
        return emails

def buscar_email_por_id(email_id):
    """Busca email específico por ID (para análise)"""
    try:
        servico_email = get_gmail_service()
        if not servico_email:
            return None
        # Busca email específico
        message = servico_email.users().messages().get(userId='me', id=email_id, format='full').execute()
        # Extrai remetente, assunto, data
        headers = message.get('payload', {}).get('headers', [])
        remetente = assunto = data = ''
        for header in headers:
            if header['name'] == 'From':
                remetente = header['value']
            elif header['name'] == 'Subject':
                assunto = header['value']
            elif header['name'] == 'Date':
                data = header['value']
        # Extrai conteúdo para análise
        conteudo = extrair_conteudo_email(message, servico_email, remetente, assunto, data)
        return conteudo.get('texto_ia') or conteudo.get('texto_simples') or f"Email ID: {email_id} - Conteúdo não disponível para análise"
    except Exception as e:
        log_otimizado(f"Erro ao buscar email por ID {email_id}: {str(e)}", 'error', forcar=True)
        return f"Erro ao acessar email: {str(e)}"

# FUNÇÕES AUXILIARES PARA TERMOS E SESSÃO
def verificar_termos_aceitos():
    """Verifica se o usuário aceitou os termos e se a sessão ainda é válida"""
    try:
        if 'termos_aceitos' not in session or 'termos_timestamp' not in session:
            return False
        
        timestamp_termos = datetime.fromisoformat(session['termos_timestamp'])
        now = datetime.now()
        
        if (now - timestamp_termos).total_seconds() > 1800:  # 30 minutos
            session.pop('termos_aceitos', None)
            session.pop('termos_timestamp', None)
            return False
        
        return session['termos_aceitos'] == True
    except Exception as e:
        log_otimizado(f"Erro ao verificar termos: {str(e)}", 'error', forcar=True)
        session.pop('termos_aceitos', None)
        session.pop('termos_timestamp', None)
        return False

def marcar_termos_aceitos():
    """Marca que o usuário aceitou os termos"""
    try:
        session['termos_aceitos'] = True
        session['termos_timestamp'] = datetime.now().isoformat()
        session.permanent = True
        session.modified = True
        log_otimizado("✓ Termos aceitos", 'info')
    except Exception as e:
        log_otimizado(f"Erro ao marcar termos: {str(e)}", 'error', forcar=True)

def limpar_termos():
    """Limpa a aceitação dos termos"""
    try:
        session.pop('termos_aceitos', None)
        session.pop('termos_timestamp', None)
        session.modified = True
    except Exception as e:
        log_otimizado(f"Erro ao limpar termos: {str(e)}", 'error', forcar=True)

# FUNÇÕES DE INICIALIZAÇÃO DE SESSÃO OTIMIZADAS
def inicializar_sessao_site():
    """Inicializa os dados de análise de site para o usuário atual"""
    try:
        if 'site_valores' not in session:
            session['site_valores'] = ['nenhum site foi inserido']
        
        if 'site_pytohtmllist' not in session:
            session['site_pytohtmllist'] = [
                'Site Pendente',
                'Aqui forneceremos dados a respeito da notabilidade do site',
                'Aqui reportaremos informações sobre o julgamento do site',
                'Aqui recomendaremos medidas de segurança gerais',
                '0',
                "#58697a"
            ]
        
        if 'site_natureza_analisada' not in session:
            session['site_natureza_analisada'] = False
        
        if 'site_resultado_natureza' not in session:
            session['site_resultado_natureza'] = None
        
        # Marca timestamp da última atividade
        session['last_activity'] = datetime.now().isoformat()
        session.permanent = True
        log_otimizado("✓ Sessão de site inicializada", 'info')
    except Exception as e:
        log_otimizado(f"Erro ao inicializar sessão site: {str(e)}", 'error', forcar=True)

def inicializar_sessao_email():
    """Inicializa os dados de análise de email para o usuário atual - OTIMIZADA"""
    try:
        # APENAS dados mínimos na sessão
        if 'email_pytohtmllist02' not in session:
            session['email_pytohtmllist02'] = [
                'Email Pendente',
                'Aqui forneceremos dados a respeito da notabilidade do autor do email',
                'Aqui reportaremos informações sobre o julgamento do conteúdo geral do email',
                'Aqui recomendaremos medidas de segurança gerais',
                '0',
                "#58697a",
                'Assunto do email'
            ]
        
        if 'email_quesito' not in session:
            session['email_quesito'] = False
        
        if 'email_filtros' not in session:
            session['email_filtros'] = {}
        
        if 'email_analisaremail' not in session:
            session['email_analisaremail'] = False
        
        if 'email_filtro_on' not in session:
            session['email_filtro_on'] = False
        
        # Nova variável para categoria atual de emails
        if 'email_categoria_atual' not in session:
            session['email_categoria_atual'] = 'INBOX'
        
        # NOVO: Estado de carregamento
        if 'emails_carregados' not in session:
            session['emails_carregados'] = False
        
        # Marca timestamp da última atividade
        session['last_activity'] = datetime.now().isoformat()
        session.permanent = True
        log_otimizado("✓ Sessão de email inicializada (otimizada)", 'info')
    except Exception as e:
        log_otimizado(f"Erro ao inicializar sessão email: {str(e)}", 'error', forcar=True)

def verificar_timeout_sessao():
    """Verifica se a sessão expirou por inatividade e limpa se necessário"""
    try:
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            now = datetime.now()
            
            # Se passou mais de 30 minutos, limpa a sessão
            if (now - last_activity).total_seconds() > 1800:  # 30 minutos
                limpar_sessao_completa()
                return True
        return False
    except Exception as e:
        log_otimizado(f"Erro ao verificar timeout: {str(e)}", 'error', forcar=True)
        limpar_sessao_completa()
        return True

def limpar_sessao_site():
    """Limpa apenas os dados de análise de site da sessão"""
    try:
        keys_to_remove = [
            'site_valores', 'site_pytohtmllist', 'site_natureza_analisada', 
            'site_resultado_natureza'
        ]
        for key in keys_to_remove:
            session.pop(key, None)
        
        # Reinicializa com valores padrão
        inicializar_sessao_site()
        log_otimizado("✓ Sessão de site limpa", 'info')
    except Exception as e:
        log_otimizado(f"Erro ao limpar sessão site: {str(e)}", 'error', forcar=True)

def limpar_sessao_email():
    """Limpa apenas os dados de análise de email da sessão (não remove credenciais OAuth)"""
    try:
        keys_to_remove = [
            'email_pytohtmllist02', 'email_quesito', 'email_filtros',
            'email_analisaremail', 'email_filtro_on', 'email_categoria_atual',
            'emails_carregados'
        ]
        for key in keys_to_remove:
            session.pop(key, None)
        
        # Limpa cache de emails do usuário atual
        limpar_cache_usuario()
        
        # Limpa cache de análises
        limpar_cache_analises_usuario()
        
        # Reinicializa com valores padrão
        inicializar_sessao_email()
        log_otimizado("✓ Sessão de email limpa (mantendo OAuth)", 'debug')
    except Exception as e:
        log_otimizado(f"Erro ao limpar sessão email: {str(e)}", 'error', forcar=True)

def limpar_sessao_oauth():
    """Limpa apenas as variáveis OAuth temporárias, mantendo credenciais válidas"""
    try:
        # Remove apenas dados temporários do fluxo OAuth
        keys_to_remove = [
            'oauth_state', 'oauth_flow_data', 
            'oauth_in_progress', 'oauth_scopes', 'oauth_timestamp'
        ]
        for key in keys_to_remove:
            session.pop(key, None)
        log_otimizado("✓ Dados temporários OAuth limpos", 'debug')
    except Exception as e:
        log_otimizado(f"Erro ao limpar OAuth temporário: {str(e)}", 'error', forcar=True)

def limpar_oauth_completo():
    """Limpa completamente todos os dados OAuth incluindo credenciais"""
    try:
        # Limpa cache de emails antes de limpar OAuth
        limpar_cache_usuario()
        
        # Limpa cache de análises
        limpar_cache_analises_usuario()
        
        keys_to_remove = [
            'oauth_state', 'oauth_error', 'oauth_flow_data', 
            'oauth_in_progress', 'oauth_scopes', 'oauth_timestamp',
            'oauth_credentials', 'oauth_authenticated', 'emails_carregados'
        ]
        for key in keys_to_remove:
            session.pop(key, None)
        log_otimizado("✓ OAuth completamente limpo", 'debug')
    except Exception as e:
        log_otimizado(f"Erro ao limpar OAuth completo: {str(e)}", 'error', forcar=True)

def limpar_sessao_completa():
    """Limpa completamente a sessão do usuário"""
    try:
        # Limpa cache de emails antes de limpar sessão
        limpar_cache_usuario()
        
        # Limpa cache de análises
        limpar_cache_analises_usuario()
        
        session.clear()
        log_otimizado("✓ Sessão completamente limpa", 'debug')
    except Exception as e:
        log_otimizado(f"Erro ao limpar sessão completa: {str(e)}", 'error', forcar=True)

def get_gmail_service():
    """Obtém o serviço Gmail se autenticado"""
    try:
        if not session.get('oauth_authenticated') or not session.get('oauth_credentials'):
            return None
        
        if EMAIL_INNIT_AVAILABLE:
            # Sempre recria o serviço usando as credenciais salvas
            return criar_servico_gmail(session['oauth_credentials'])
        else:
            return None
    except Exception as e:
        log_otimizado(f"Erro ao obter Gmail service: {str(e)}", 'error', forcar=True)
        return None

def buscar_emails_atuais(categoria='INBOX', limite=25):
    """Busca emails atuais do usuário autenticado por categoria - agora usando sessão server-side"""
    try:
        # Primeiro tenta obter da sessão
        emails_sessao = obter_emails_sessao(categoria)
        if emails_sessao:
            emails_verificados = verificar_propriedade_emails(emails_sessao)
            if emails_verificados:
                return emails_verificados

        # Se não tem na sessão, busca do Gmail
        servico_email = get_gmail_service()
        if not servico_email:
            return []

        emails = buscar_emails_por_categoria(servico_email, categoria, limite)
        emails_verificados = verificar_propriedade_emails(emails)

        # Salva na sessão apenas se passou na verificação
        if emails_verificados:
            salvar_emails_sessao(emails_verificados, categoria)

        log_otimizado(f"✓ {len(emails_verificados)} emails verificados da categoria {categoria}", 'info')
        return emails_verificados
    except Exception as e:
        log_otimizado(f"Erro ao buscar emails da categoria {categoria}: {str(e)}", 'error', forcar=True)
        return []

def obter_categorias_emails():
    """Obtém as categorias de emails disponíveis com contagem"""
    try:
        servico_email = get_gmail_service()
        if not servico_email:
            return {}
        
        categorias = obter_categorias_disponiveis(servico_email)
        log_otimizado(f"✓ Categorias obtidas: {list(categorias.keys())}", 'info')
        return categorias
    except Exception as e:
        log_otimizado(f"Erro ao obter categorias: {str(e)}", 'error', forcar=True)
        return {}

def aplicar_filtros_emails(emails, filtros):
    """Aplica filtros aos emails sem armazenar na sessão"""
    try:
        if not emails or not filtros:
            return emails
        
        emails_filtrados = emails.copy()
        
        # Filtro por data
        if filtros.get('data') and len(filtros['data']) > 2:
            resultado_data = data(emails_filtrados, filtros['data'])
            if isinstance(resultado_data, dict) and 'Resultado' in resultado_data:
                return {'error': resultado_data['Resultado']}
            emails_filtrados = resultado_data
        
        # Filtro por autor
        if filtros.get('autor') and len(filtros['autor']) > 2:
            resultado_autor = remetentes(emails_filtrados, filtros['autor'])
            if isinstance(resultado_autor, dict) and 'Resultado' in resultado_autor:
                return {'error': resultado_autor['Resultado']}
            emails_filtrados = resultado_autor
        
        return emails_filtrados
    except Exception as e:
        log_otimizado(f"Erro ao aplicar filtros: {str(e)}", 'error', forcar=True)
        return {'error': f"Erro ao aplicar filtros: {str(e)}"}

# FUNÇÕES DE CACHE DE ANÁLISES - NOVA OTIMIZAÇÃO
def obter_analise_cache(email_id):
    """
    Obtém análise do cache se existir e não estiver expirada
    """
    try:
        if email_id in analysis_cache:
            cache_data = analysis_cache[email_id]
            
            # Verifica se não expirou (1 hora)
            if (datetime.now() - cache_data['timestamp']).total_seconds() < 3600:
                log_otimizado(f"✓ Análise obtida do cache para email {email_id}", 'debug')
                return cache_data['resultado']
            else:
                # Remove análise expirada
                del analysis_cache[email_id]
                log_otimizado(f"✓ Análise expirada removida do cache: {email_id}", 'debug')
        
        return None
    except Exception as e:
        log_otimizado(f"Erro ao obter análise do cache: {str(e)}", 'error', forcar=True)
        return None

def salvar_analise_cache(email_id, resultado):
    """
    Salva resultado de análise no cache
    """
    try:
        analysis_cache[email_id] = {
            'resultado': resultado,
            'timestamp': datetime.now()
        }
        log_otimizado(f"✓ Análise salva no cache para email {email_id}", 'debug')
        
        # Limpa análises expiradas periodicamente
        if len(analysis_cache) > 100:  # Se cache muito grande
            limpar_analises_expiradas()
            
    except Exception as e:
        log_otimizado(f"Erro ao salvar análise no cache: {str(e)}", 'error', forcar=True)

def limpar_analises_expiradas():
    """
    Limpa análises expiradas do cache
    """
    try:
        current_time = datetime.now()
        keys_to_remove = []
        
        for email_id, cache_data in analysis_cache.items():
            if (current_time - cache_data['timestamp']).total_seconds() > 3600:  # 1 hora
                keys_to_remove.append(email_id)
        
        for email_id in keys_to_remove:
            del analysis_cache[email_id]
        
        if keys_to_remove:
            log_otimizado(f"✓ {len(keys_to_remove)} análises expiradas removidas", 'debug')
            
    except Exception as e:
        log_otimizado(f"Erro ao limpar análises expiradas: {str(e)}", 'error', forcar=True)

def limpar_cache_analises_usuario(user_id=None):
    """
    Limpa cache de análises do usuário específico
    """
    try:
        if user_id is None:
            # Limpa todas as análises (usuário fez logout)
            analysis_cache.clear()
            log_otimizado("✓ Cache de análises limpo completamente", 'debug')
        else:
            # Limpa análises de usuário específico (se implementar identificação por usuário)
            keys_to_remove = []
            for email_id in analysis_cache.keys():
                # Por enquanto, limpa todas as análises
                # Futuro: implementar identificação por usuário
                keys_to_remove.append(email_id)
            
            for email_id in keys_to_remove:
                del analysis_cache[email_id]
            
            log_otimizado(f"✓ Cache de análises limpo para usuário", 'debug')
            
    except Exception as e:
        log_otimizado(f"Erro ao limpar cache de análises: {str(e)}", 'error', forcar=True)

# MIDDLEWARE PARA VERIFICAR TIMEOUT EM TODAS AS ROTAS
@app.before_request
def before_request():
    """Verifica timeout apenas se não for uma rota de assets estáticos"""
    try:
        if not request.endpoint or not request.endpoint.startswith('static'):
            if verificar_timeout_sessao():
                flash("Sessão expirada por inatividade. Dados limpos.", "info")
    except Exception as e:
        log_otimizado(f"Erro no before_request: {str(e)}", 'error', forcar=True)

# DECORATOR PARA VERIFICAR TERMOS ACEITOS
def requer_termos_aceitos(f):
    """Decorator que verifica se o usuário aceitou os termos antes de acessar a rota"""
    def decorated_function(*args, **kwargs):
        try:
            if not verificar_termos_aceitos():
                flash("Você precisa aceitar os Termos e Condições para acessar esta página.", "error")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        except Exception as e:
            log_otimizado(f"Erro no decorator: {str(e)}", 'error', forcar=True)
            return redirect(url_for('home'))
    decorated_function.__name__ = f.__name__
    return decorated_function

# ROTAS BÁSICAS
@app.route("/")
def home():
    """Rota principal"""
    try:
        log_otimizado("=== HOME ===", 'info')
        limpar_sessao_completa()  # Limpa tudo ao entrar na página inicial
        return render_template("mainhome.html")
    except Exception as e:
        log_otimizado(f"ERRO home: {str(e)}", 'error', forcar=True)
        return f"Erro: {str(e)}", 500

@app.route("/aceitar_termos", methods=["POST"])
def aceitar_termos():
    """Processa aceitação dos termos"""
    try:
        log_otimizado("=== ACEITAR TERMOS ===", 'info')
        aceitar = request.form.get("aceitar")
        
        if aceitar == "sim":
            # Usuário aceitou os termos
            marcar_termos_aceitos()
            flash("Termos aceitos com sucesso! Bem-vindo à Evita.", "success")
            return redirect(url_for('info'))
        else:
            # Usuário não aceitou os termos
            limpar_termos()
            flash("Você deve aceitar os Termos e Condições para prosseguir.", "error")
            return redirect(url_for('home'))
    except Exception as e:
        log_otimizado(f"Erro aceitar termos: {str(e)}", 'error', forcar=True)
        return redirect(url_for('home'))

@app.route("/info")
@requer_termos_aceitos
def info():
    """Rota de seleção de opções (protegida)"""
    try:
        # Atualiza timestamp de atividade
        session['last_activity'] = datetime.now().isoformat()
        session.modified = True
        return render_template("index.html")
    except Exception as e:
        log_otimizado(f"ERRO info: {str(e)}", 'error', forcar=True)
        return f"Erro: {str(e)}", 500

# NOVA ROTA PARA PLANOS
@app.route("/plans")
def plans():
    """Rota da página de planos (protegida)"""
    try:
        log_otimizado("=== PLANOS ===", 'info')
        # Atualiza timestamp de atividade
        session['last_activity'] = datetime.now().isoformat()
        session.modified = True
        return render_template("plans.html")
    except Exception as e:
        log_otimizado(f"ERRO plans: {str(e)}", 'error', forcar=True)
        return f"Erro: {str(e)}", 500

# ROTAS DE ANÁLISE DE SITE (INTEGRADAS DO ARQUIVO ANTIGO)
@app.route("/siteanalysis", methods=["GET", "POST"])
@requer_termos_aceitos
def site():
    """Rota de análise do site (protegida)"""
    try:
        log_otimizado("=== SITE ANALYSIS ===", 'info')
        
        # Verifica se módulos estão disponíveis
        if not SITE_ANALISE_SITE_AVAILABLE:
            flash("Módulo de análise de site não disponível.", "error")
            return redirect(url_for('info'))
        
        # Inicializa sessão do usuário
        inicializar_sessao_site()
        
        # Lista de imagens EVA disponíveis
        eva_images = [f for f in os.listdir('static') if f.startswith('eva') and f.endswith('.png')]
        # Embaralha a lista de imagens
        random.shuffle(eva_images)
        # Garante que temos pelo menos 3 imagens (repete se necessário)
        while len(eva_images) < 3:
            eva_images.extend(eva_images)
        # Pega as 3 primeiras imagens
        random_eva_images = eva_images[:3]
        
        # CRIANDO INPUT DE SITE
        if request.method == "POST":
            novo_valor = request.form.get("valor")
            if novo_valor:
                # Atualiza valores na sessão do usuário
                session['site_valores'] = [novo_valor]
                try:
                    # Análise completa (classificação + relatório) usando prompt unificado
                    resultado_completo = apichatgptsite(session['site_valores'])
                    session['site_pytohtmllist'] = resultado_completo

                    # Variáveis mantidas por compatibilidade, embora não sejam mais usadas
                    session['site_natureza_analisada'] = True
                    session['site_resultado_natureza'] = resultado_completo

                    # Atualiza timestamp de atividade
                    session['last_activity'] = datetime.now().isoformat()
                    session.modified = True

                    flash("Análise completa gerada com sucesso!", "success")
                except Exception as e:
                    log_otimizado(f"Erro na análise de site: {str(e)}", 'error', forcar=True)
                    flash(f"Erro na análise: {str(e)}", "error")

            return redirect(url_for("site"))
        
        # RENDERIZANDO SITE E ENVIANDO VALORES DA SESSÃO PARA O HTML
        template_data = {
            'valores': session['site_valores'], 
            'classificacao': session['site_pytohtmllist'][0],
            'reputacao': session['site_pytohtmllist'][1],
            'justificativa': session['site_pytohtmllist'][2],
            'seguranca': session['site_pytohtmllist'][3],
            'coloracao': session['site_pytohtmllist'][5],
            'natureza_analisada': session['site_natureza_analisada'],
            'random_eva_images': random_eva_images  # Adiciona as imagens randomizadas
        }
        
        return render_template("siteanalysis.html", **template_data)
        
    except Exception as e:
        log_otimizado(f"ERRO GERAL site: {str(e)}", 'error', forcar=True)
        traceback.print_exc()
        flash(f"Erro na análise de site: {str(e)}", "error")
        return redirect(url_for('info'))

@app.route("/gerar_relatorio", methods=["POST"])
@requer_termos_aceitos
def gerar_relatorio():
    """Rota para gerar relatório completo (protegida)"""
    try:
        log_otimizado("=== GERAR RELATÓRIO ===", 'info')
        
        if not SITE_RELATORIO_AVAILABLE:
            flash("Módulo de relatório não disponível.", "error")
            return redirect(url_for('site'))
        
        inicializar_sessao_site()
        
        if (len(session['site_valores']) > 0 and 
            session['site_valores'][0] != 'nenhum site foi inserido'):
            try:
                # Análise completa diretamente (prompt unificado)
                relatorio_completo = apichatgptsite(session['site_valores'])
                session['site_pytohtmllist'] = relatorio_completo
                session['last_activity'] = datetime.now().isoformat()
                session.modified = True
                flash("Relatório completo gerado com sucesso!", "success")

                if session['site_pytohtmllist'][5] in ["#58697a", "#733179"]:
                    flash("Site pode ter problemas de validação.", "warning")
            except Exception as e:
                log_otimizado(f"Erro ao gerar relatório: {str(e)}", 'error', forcar=True)
                flash(f"Erro ao gerar relatório: {str(e)}", "error")
        else:
            flash("Digite primeiro o site a ser analisado.", "warning")
    
        return redirect(url_for("site"))
        
    except Exception as e:
        log_otimizado(f"Erro gerar_relatorio: {str(e)}", 'error', forcar=True)
        flash(f"Erro: {str(e)}", "error")
        return redirect(url_for("site"))

@app.route("/reset_analise")
@requer_termos_aceitos
def reset_analise():
    """Rota para resetar análise de site (protegida)"""
    try:
        log_otimizado("=== RESET ANÁLISE SITE ===", 'info')
        limpar_sessao_site()
        flash("Análise de site resetada", "info")
        return redirect(url_for("site"))
    except Exception as e:
        log_otimizado(f"Erro reset_analise: {str(e)}", 'error', forcar=True)
        flash(f"Erro: {str(e)}", "error")
        return redirect(url_for("site"))

# NOVA ROTA DE PROCESSAMENTO DE EMAILS (AJAX)
@app.route("/process_emails_ajax")
@requer_termos_aceitos
def process_emails_ajax():
    """Processa emails via AJAX para feedback em tempo real"""
    try:
        log_otimizado("=== PROCESS EMAILS AJAX ===", 'info')
        
        if not session.get('oauth_authenticated'):
            return jsonify({'status': 'error', 'message': 'Não autenticado'})
        
        inicializar_sessao_email()
        
        # Busca categorias disponíveis
        categorias = obter_categorias_emails()
        
        # Busca emails da categoria atual
        categoria_atual = session.get('email_categoria_atual', 'INBOX')
        emails = buscar_emails_atuais(categoria_atual, 25)
        
        # Marca como carregados na sessão (apenas flag boolean)
        session['emails_carregados'] = True
        session['last_activity'] = datetime.now().isoformat()
        session.modified = True
        
        return jsonify({
            'status': 'success',
            'message': f'{len(emails)} emails carregados da categoria {categoria_atual}',
            'total_emails': len(emails),
            'categoria': categoria_atual,
            'categorias_disponiveis': len(categorias)
        })
        
    except Exception as e:
        log_otimizado(f"Erro process_emails_ajax: {str(e)}", 'error', forcar=True)
        return jsonify({'status': 'error', 'message': str(e)})

# ROTAS DE ANÁLISE DE EMAIL (REFATORADAS COM CATEGORIAS E OTIMIZADAS)
@app.route("/emailanalysis", methods=["GET", "POST"])
@requer_termos_aceitos
def email():
    """Rota de análise de email (protegida) - OTIMIZADA"""
    try:
        log_otimizado("=== EMAIL ANALYSIS ===", 'info')
        
        # Inicializar sessão
        inicializar_sessao_email()
        
        # Dados básicos da sessão (mínimos)
        oauth_authenticated = session.get('oauth_authenticated', False)
        oauth_error = session.get('oauth_error')
        categoria_atual = session.get('email_categoria_atual', 'INBOX')
        emails_carregados = session.get('emails_carregados', False)
        
        # Lista de imagens EVA disponíveis
        eva_images = [f for f in os.listdir('static') if f.startswith('eva') and f.endswith('.png')]
        # Embaralha a lista de imagens
        random.shuffle(eva_images)
        # Garante que temos pelo menos 4 imagens (repete se necessário)
        while len(eva_images) < 4:
            eva_images.extend(eva_images)
        # Pega as 4 primeiras imagens
        random_eva_images = eva_images[:4]
        
        log_otimizado(f"OAuth autenticado: {oauth_authenticated}", 'debug')
        log_otimizado(f"Emails carregados: {emails_carregados}", 'debug')
        log_otimizado(f"Categoria atual: {categoria_atual}", 'debug')
        
        # Verifica se há erro de OAuth na sessão
        if not oauth_authenticated and not oauth_error:
            flash("Faça login com sua conta Google para acessar os emails", "info")
        
        # Processa o resultado da análise se quesito for True
        if session.get('email_quesito') == True: 
            session['email_quesito'] = False
            session.modified = True
        
        # Processar POST - novos filtros
        if request.method == 'POST':
            try:
                filtro = request.form.get('filtro')
                valor = request.form.get(filtro)
                if filtro and valor:
                    # Adiciona ou atualiza o filtro na sessão (dados pequenos)
                    if 'email_filtros' not in session:
                        session['email_filtros'] = {}
                    session['email_filtros'][filtro] = valor
                    session['last_activity'] = datetime.now().isoformat()
                    session.modified = True
                    log_otimizado(f"Filtro aplicado: {filtro} = {valor}", 'debug')
                return redirect(url_for('email'))
            except Exception as e:
                log_otimizado(f"Erro POST: {str(e)}", 'error', forcar=True)
                flash("Erro ao aplicar filtro.", "error")
        
        # Buscar emails dinamicamente (do cache ou Gmail)
        emails_totais = []
        email_categories = {}
        
        if oauth_authenticated and EMAIL_INNIT_AVAILABLE:
            if emails_carregados:
                log_otimizado(f"🔄 Buscando emails da categoria: {categoria_atual}", 'debug')
                emails_totais = buscar_emails_atuais(categoria_atual, 25)
                
                # Obter categorias disponíveis com contagem
                email_categories = obter_categorias_emails()
                
                # Aplicar filtros se existirem
                filtros = session.get('email_filtros', {})
                if filtros:
                    log_otimizado(f"🔄 Aplicando filtros: {filtros}", 'debug')
                    resultado_filtros = aplicar_filtros_emails(emails_totais, filtros)
                    if isinstance(resultado_filtros, dict) and 'error' in resultado_filtros:
                        flash(resultado_filtros['error'], "warning")
                    else:
                        emails_totais = resultado_filtros
                        session['email_filtro_on'] = True
                else:
                    session['email_filtro_on'] = False
        
        log_otimizado(f"✓ {len(emails_totais)} emails para exibir da categoria {categoria_atual}", 'info')
        
        # Preparar dados do template de forma segura
        email_data = session.get('email_pytohtmllist02', [
            'Email Pendente', 
            'Aqui forneceremos dados a respeito da notabilidade do autor do email',
            'Aqui reportaremos informações sobre o julgamento do conteúdo geral do email',
            'Aqui recomendaremos medidas de segurança gerais',
            '0', 
            "#58697a", 
            'Assunto do email'
        ])
        
        # Garantir que temos dados suficientes
        while len(email_data) < 7:
            email_data.append('Pendente')
        
        template_data = {
            'filtros': session.get('email_filtros', {}),
            'classificacao02': email_data[0],
            'dominio02': email_data[1],
            'justificativa02': email_data[2],
            'seguranca02': email_data[3],
            'coloracao': email_data[5],
            'assuntoemail': email_data[6],
            'emails_totais': emails_totais,  # Emails buscados dinamicamente
            'oauth_authenticated': oauth_authenticated,
            'oauth_error': oauth_error,
            'email_categories': email_categories,  # Categorias disponíveis
            'categoria_atual': categoria_atual,  # Categoria atualmente selecionada
            'emails_carregados': emails_carregados,  # NOVO: Estado de carregamento
            'random_eva_images': random_eva_images  # Adiciona as imagens randomizadas ao template
        }
        
        log_otimizado("✓ Dados preparados, renderizando template...", 'debug')
        
        return render_template("emailanalysis.html", **template_data)
        
    except Exception as e:
        log_otimizado(f"ERRO GERAL email: {str(e)}", 'error', forcar=True)
        traceback.print_exc()
        
        # Página de erro simples
        return f"""
        <html>
        <head><title>Erro - Evita</title></head>
        <body style="font-family: Arial; padding: 40px; background: #f0f0f0;">
        <h1>Erro 502</h1>
        <p>Problema de comunicação com o servidor.</p>
        <p><a href="/">Voltar ao início</a></p>
        </body>
        </html>
        """, 502

# NOVA ROTA PARA MUDANÇA DE CATEGORIA - CORRIGIDA
@app.route('/mudar_categoria', methods=['POST'])
@requer_termos_aceitos
def mudar_categoria():
    """Muda a categoria de emails sendo visualizada - OTIMIZADO: cache por categoria, sem limpar ao trocar"""
    try:
        log_otimizado("=== MUDAR CATEGORIA ===", 'info')
        inicializar_sessao_email()
        categoria_anterior = session.get('email_categoria_atual', 'INBOX')
        nova_categoria = request.form.get('categoria', 'INBOX')
        # Validar categoria
        if nova_categoria not in ['INBOX', 'SPAM', 'IMPORTANT', 'STARRED', 'ALL']:
            nova_categoria = 'INBOX'
        # Atualizar categoria na sessão
        session['email_categoria_atual'] = nova_categoria
        session['last_activity'] = datetime.now().isoformat()
        session.modified = True
        # Limpar filtros ao mudar categoria
        session['email_filtros'] = {}
        session['email_filtro_on'] = False
        # Reset da análise ao mudar categoria
        session['email_pytohtmllist02'] = [
            'Email Pendente',
            'Aqui forneceremos dados a respeito da notabilidade do autor do email',
            'Aqui reportaremos informações sobre o julgamento do conteúdo geral do email',
            'Aqui recomendaremos medidas de segurança gerais',
            '0',
            "#58697a",
            'Assunto do email'
        ]
        # Busca emails da nova categoria: só busca do Gmail se não estiver em cache
        try:
            emails = obter_emails_sessao(nova_categoria)
            if not emails:
                emails = buscar_emails_atuais(nova_categoria, 25)
            if not emails:
                categoria_nome = EMAIL_CATEGORIES.get(nova_categoria, nova_categoria)
                flash(f"Não há emails na categoria: {categoria_nome}", "info")
            else:
                categoria_nome = EMAIL_CATEGORIES.get(nova_categoria, nova_categoria)
                flash(f"Visualizando emails de: {categoria_nome} ({len(emails)} emails)", "success")
        except Exception as e:
            log_otimizado(f"Erro ao buscar emails da categoria {nova_categoria}: {str(e)}", 'error', forcar=True)
            flash(f"Erro ao carregar categoria: {str(e)}", "error")
        log_otimizado(f"✓ Categoria alterada para: {nova_categoria}", 'info')
        return redirect(url_for('email'))
    except Exception as e:
        log_otimizado(f"Erro mudar_categoria: {str(e)}", 'error', forcar=True)
        flash("Erro ao mudar categoria.", "error")
        return redirect(url_for('email'))

# ROTAS OAUTH PARA EMAIL (CORRIGIDAS)
if EMAIL_INNIT_AVAILABLE:
    @app.route("/logingoogle")
    @requer_termos_aceitos
    def logingoogle():
        """Inicia login OAuth com Google"""
        try:
            log_otimizado("=== LOGIN GOOGLE ===", 'info')
            
            # Debug do ambiente
            log_otimizado(f"HOST: {request.host}", 'debug')
            log_otimizado(f"URL: {request.url}", 'debug')
            
            # Limpa apenas dados OAuth temporários, não credenciais válidas
            limpar_sessao_oauth()
            
            # Gera um novo state único para esta tentativa
            unique_state = secrets.token_urlsafe(32)
            log_otimizado(f"State único gerado: {unique_state}", 'debug')
            
            # Inicia o fluxo OAuth
            oauth_result = iniciar_flow_oauth(unique_state)
            
            if oauth_result['success']:
                log_otimizado(f"✓ Redirect URI determinado: {oauth_result['redirect_uri']}", 'info')
                
                # Configura a sessão como permanente
                session.permanent = True

                # Salva dados do fluxo OAuth na sessão
                session['oauth_state'] = oauth_result['state']
                session['oauth_scopes'] = oauth_result['scopes']
                session['oauth_in_progress'] = True
                session['oauth_timestamp'] = datetime.now().isoformat()
                session['last_activity'] = datetime.now().isoformat()

                # Força a gravação da sessão
                session.modified = True

                log_otimizado(f"✓ Estado OAuth salvo: {session.get('oauth_state')}", 'debug')
                log_otimizado(f"✓ Redirecionando para Google...", 'info')

                # Redireciona para a URL de autorização do Google
                return redirect(oauth_result['authorization_url'])
            else:
                # Em caso de erro, salva na sessão e redireciona para email
                session['oauth_error'] = f"Erro ao iniciar login: {oauth_result['error']}"
                flash(f"Erro ao iniciar login: {oauth_result['error']}", "error")
                return redirect(url_for('email'))
            
        except Exception as e:
            limpar_oauth_completo()
            error_msg = f"Erro inesperado ao iniciar login: {str(e)}"
            session['oauth_error'] = error_msg
            flash(error_msg, "error")
            log_otimizado(f"ERRO no logingoogle: {str(e)}", 'error', forcar=True)
            traceback.print_exc()
            return redirect(url_for('email'))

    @app.route("/oauth/callback")
    @requer_termos_aceitos
    def oauth_callback():
        """Callback do OAuth - CORRIGIDO para redirecionar para loading"""
        try:
            log_otimizado("=== OAUTH CALLBACK ===", 'info')
            log_otimizado(f"URL completa recebida: {request.url}", 'debug')
            
            # Verifica se há erro na resposta do Google
            error = request.args.get('error')
            if error:
                error_description = request.args.get('error_description', 'Sem descrição')
                log_otimizado(f"❌ Erro do Google: {error} - {error_description}", 'warning')
                limpar_oauth_completo()
                session['oauth_error'] = f"Autorização negada pelo Google: {error} - {error_description}"
                flash("Login cancelado ou negado pelo usuário", "error")
                return redirect(url_for('email'))
            
            # Verifica se há um fluxo OAuth em progresso
            oauth_in_progress = session.get('oauth_in_progress')
            oauth_state = session.get('oauth_state')

            if not oauth_in_progress or not oauth_state:
                log_otimizado("❌ Nenhum fluxo OAuth encontrado na sessão", 'warning')
                limpar_oauth_completo()
                session['oauth_error'] = "Sessão OAuth não encontrada ou expirada"
                flash("Sessão expirada. Tente fazer login novamente.", "error")
                return redirect(url_for('email'))
            
            # Pega dados da sessão
            expected_state = session.get('oauth_state')
            original_scopes = session.get('oauth_scopes')
            received_state = request.args.get('state')
            
            log_otimizado(f"Estado esperado: {expected_state}", 'debug')
            log_otimizado(f"Estado recebido: {received_state}", 'debug')
            
            # Verificação de estado
            if expected_state != received_state:
                log_otimizado(f"❌ Estados não coincidem!", 'warning')
                limpar_oauth_completo()
                flash("Erro de segurança OAuth. Tente fazer login novamente.", "error")
                return redirect(url_for('email'))
            
            log_otimizado("✓ Verificações de segurança passaram, finalizando OAuth...", 'debug')

            # Finaliza o OAuth
            authorization_response = request.url
            oauth_result = finalizar_oauth(authorization_response, expected_state, original_scopes)

            if oauth_result['success']:
                log_otimizado("✅ OAuth finalizado com sucesso!", 'info')
                
                # Salva apenas credenciais serializáveis na sessão
                session['oauth_credentials'] = oauth_result['credentials_data']
                session['oauth_authenticated'] = True
                session['emails_carregados'] = False  # NOVO: Marca que emails não foram carregados ainda
                session['last_activity'] = datetime.now().isoformat()
                
                # Limpa dados temporários OAuth
                limpar_sessao_oauth()
                
                flash("Login realizado com sucesso! Carregando seus emails...", "success")
                
                # CORREÇÃO: Redireciona para email com estado de loading
                return redirect(url_for('email'))
            else:
                log_otimizado(f"❌ Erro na finalização OAuth: {oauth_result['error']}", 'error')
                limpar_oauth_completo()
                session['oauth_error'] = oauth_result['error']
                flash(f"Erro na autenticação: {oauth_result['error']}", "error")
                return redirect(url_for('email'))
                
        except Exception as e:
            log_otimizado(f"💥 Exceção no callback: {str(e)}", 'error', forcar=True)
            traceback.print_exc()
            
            limpar_oauth_completo()
            error_msg = f"Erro interno na autenticação: {str(e)}"
            session['oauth_error'] = error_msg
            flash("Erro interno na autenticação. Tente novamente.", "error")
            return redirect(url_for('email'))
else:
    @app.route("/logingoogle")
    @requer_termos_aceitos
    def logingoogle():
        flash("Módulo de email não disponível.", "error")
        return redirect(url_for('email'))

# ROTAS DE FILTRO E ANÁLISE DE EMAIL (CORRIGIDAS)
@app.route('/limpar', methods=['POST'])
@requer_termos_aceitos
def limpar():
    """Limpa filtros de email"""
    try:
        log_otimizado("=== LIMPAR FILTROS ===", 'info')
        inicializar_sessao_email()
        
        # Reset das variáveis de análise na sessão
        session['email_pytohtmllist02'] = [
            'Email Pendente',
            'Aqui forneceremos dados a respeito da notabilidade do autor do email',
            'Aqui reportaremos informações sobre o julgamento do conteúdo geral do email',
            'Aqui recomendaremos medidas de segurança gerais',
            '0',
            "#58697a",
            'Assunto do email'
        ]
        session['email_filtro_on'] = False
        
        # Limpa filtros da sessão
        session['email_filtros'] = {}
        session['last_activity'] = datetime.now().isoformat()
        session.modified = True
        
        flash("Filtros limpos", "success")
        return redirect(url_for('email'))
        
    except Exception as e:
        log_otimizado(f"Erro limpar: {str(e)}", 'error', forcar=True)
        flash("Erro ao limpar.", "error")
        return redirect(url_for('email'))

@app.route('/enviar', methods=['POST'])
@requer_termos_aceitos
def enviar():
    """Aplica filtros aos emails (os filtros são aplicados dinamicamente na rota principal)"""
    try:
        log_otimizado("=== APLICAR FILTROS ===", 'info')
        # Os filtros já foram aplicados no POST da rota principal
        # Esta rota apenas redireciona de volta
        flash("Filtros aplicados", "success")
        return redirect(url_for('email'))
        
    except Exception as e:
        log_otimizado(f"Erro enviar: {str(e)}", 'error', forcar=True)
        flash(f"Erro: {str(e)}", "error")
        return redirect(url_for('email'))

@app.route('/analisaremail', methods=['POST'])
@requer_termos_aceitos
def analisaremail():
    """Analisa email específico - OTIMIZADO COM CACHE E LOGS DETALHADOS"""
    try:
        log_otimizado("=== INÍCIO ANALISAR EMAIL ===", 'info', forcar=True)
        inicializar_sessao_email()

        if not EMAIL_RELATORIO_AVAILABLE:
            log_otimizado("❌ Módulo de análise não disponível", 'error', forcar=True)
            flash("Módulo de análise não disponível.", "error")
            return redirect(url_for('email'))

        # CORREÇÃO PRINCIPAL: Aceita tanto email_id quanto email_especifico
        email_id = request.form.get("email_id")
        email_especifico = request.form.get("email_especifico")
        assunto_especifico = request.form.get("assunto_email_especifico", "Assunto não disponível")
        
        log_otimizado(f"📧 DADOS RECEBIDOS:", 'info', forcar=True)
        log_otimizado(f"  - Email ID: {email_id}", 'info', forcar=True)
        log_otimizado(f"  - Email específico: {'SIM' if email_especifico else 'NÃO'}", 'info', forcar=True)
        log_otimizado(f"  - Assunto: {assunto_especifico}", 'info', forcar=True)
        
        # Verifica se pelo menos um dos dois foi fornecido
        if not email_id and not email_especifico:
            log_otimizado("❌ Nenhum email fornecido para análise", 'error', forcar=True)
            flash("Email não selecionado para análise", "error")
            return redirect(url_for('email'))
        
        try:
            # OTIMIZAÇÃO: Verificar cache de análise primeiro
            resultado_analise = None
            if email_id:
                log_otimizado(f"🔍 Verificando cache para email ID: {email_id}", 'debug', forcar=True)
                # Verifica se já existe análise no cache
                resultado_cache = obter_analise_cache(email_id)
                if resultado_cache:
                    log_otimizado(f"✅ Análise obtida do cache para email {email_id}", 'info', forcar=True)
                    resultado_analise = resultado_cache
                else:
                    log_otimizado(f"🔍 Análise não encontrada no cache, processando...", 'debug', forcar=True)
            
            # Se não tem no cache, faz a análise
            if not resultado_analise:
                log_otimizado("🚀 INICIANDO ANÁLISE NOVA", 'info', forcar=True)
                
                # Determina qual conteúdo usar para análise
                conteudo_para_analise = None
                
                if email_id:
                    # Busca email completo por ID
                    log_otimizado(f"🔍 Buscando email por ID: {email_id}", 'debug', forcar=True)
                    conteudo_para_analise = buscar_email_por_id(email_id)
                    if not conteudo_para_analise:
                        log_otimizado(f"❌ Erro ao buscar email por ID: {email_id}", 'error', forcar=True)
                        flash("Erro ao acessar conteúdo do email", "error")
                        return redirect(url_for('email'))
                    log_otimizado(f"✅ Email encontrado por ID, tamanho: {len(conteudo_para_analise)} chars", 'debug', forcar=True)
                elif email_especifico:
                    # Usa o conteúdo fornecido diretamente
                    log_otimizado("📧 Usando conteúdo específico fornecido", 'debug', forcar=True)
                    conteudo_para_analise = email_especifico
                    log_otimizado(f"✅ Conteúdo específico, tamanho: {len(conteudo_para_analise)} chars", 'debug', forcar=True)
                
                log_otimizado(f"📝 Conteúdo para análise (primeiros 200 chars): {conteudo_para_analise[:200]}...", 'debug', forcar=True)
                
                # Chama a função de análise
                log_otimizado("🤖 Iniciando análise com IA...", 'debug', forcar=True)
                start_time = time.time()
                
                try:
                    resultado_analise = apichatgptemail(conteudo_para_analise)
                    analysis_time = time.time() - start_time
                    log_otimizado(f"✅ Análise concluída em {analysis_time:.2f} segundos", 'info', forcar=True)
                    
                    if resultado_analise:
                        log_otimizado(f"✅ Resultado da análise: {resultado_analise[0] if isinstance(resultado_analise, list) else 'N/A'}", 'debug', forcar=True)
                    else:
                        log_otimizado("❌ Resultado da análise é None", 'error', forcar=True)
                        
                except Exception as analysis_error:
                    log_otimizado(f"❌ ERRO na análise com IA: {str(analysis_error)}", 'error', forcar=True)
                    traceback.print_exc()
                    raise analysis_error
                
                # OTIMIZAÇÃO: Salva resultado no cache
                if email_id and resultado_analise:
                    log_otimizado(f"💾 Salvando análise no cache para email {email_id}", 'debug', forcar=True)
                    salvar_analise_cache(email_id, resultado_analise)
                    log_otimizado(f"✅ Análise salva no cache para email {email_id}", 'debug', forcar=True)
            
            # Adiciona o assunto ao resultado
            log_otimizado("📋 Formatando resultado final...", 'debug', forcar=True)
            if isinstance(resultado_analise, list):
                resultado_analise.append(assunto_especifico)
                log_otimizado(f"✅ Assunto adicionado ao resultado: {assunto_especifico}", 'debug', forcar=True)
            else:
                log_otimizado("⚠️ Resultado não é lista, criando formato padrão", 'warning', forcar=True)
                resultado_analise = [
                    str(resultado_analise),
                    "Análise concluída",
                    "Verifique o resultado",
                    "Mantenha-se seguro",
                    "0",
                    "#58697a",
                    assunto_especifico
                ]
            
            # Salva resultado na sessão (dados mínimos)
            log_otimizado("💾 Salvando resultado na sessão...", 'debug', forcar=True)
            session['email_pytohtmllist02'] = resultado_analise
            session['email_quesito'] = True
            session['last_activity'] = datetime.now().isoformat()
            session.modified = True
            
            log_otimizado("✅ ANÁLISE CONCLUÍDA COM SUCESSO!", 'info', forcar=True)
            log_otimizado(f"📊 Resumo final: {resultado_analise[0] if isinstance(resultado_analise, list) else 'N/A'}", 'info', forcar=True)
            flash("Análise do email concluída com sucesso!", "success")
            
        except Exception as e:
            log_otimizado(f"❌ ERRO durante análise: {str(e)}", 'error', forcar=True)
            traceback.print_exc()
            flash(f"Erro ao analisar email: {str(e)}", "error")

        return redirect(url_for('email'))
        
    except Exception as e:
        log_otimizado(f"💥 ERRO GERAL analisaremail: {str(e)}", 'error', forcar=True)
        traceback.print_exc()
        flash(f"Erro interno: {str(e)}", "error")
        return redirect(url_for('email'))

# ROTAS DE LOGOUT E LIMPEZA
@app.route('/logout')
@requer_termos_aceitos
def logout():
    """Logout/reset completo"""
    try:
        # Limpa completamente a sessão do usuário
        limpar_sessao_completa()
        flash("Logout realizado com sucesso", "success")
        return redirect(url_for('home'))
    except Exception as e:
        log_otimizado(f"Erro logout: {str(e)}", 'error', forcar=True)
        return redirect(url_for('home'))

@app.route('/cleanup_session')
def cleanup_session():
    """Rota para ser chamada quando usuário sai do site ou muda de página"""
    try:
        limpar_sessao_completa()
        return {"status": "cleaned"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.route('/save_accessibility_settings', methods=['POST'])
def save_accessibility_settings():
    """Salva as configurações de acessibilidade na sessão do usuário"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Dados não fornecidos'}), 400
            
        # Salva as configurações na sessão
        session['accessibility_settings'] = {
            'fontSize': data.get('fontSize', 0),
            'isLightMode': data.get('isLightMode', False)
        }
        session.modified = True
        session['last_activity'] = datetime.now().isoformat()
        
        return jsonify({'success': True, 'message': 'Configurações salvas com sucesso'})
    except Exception as e:
        log_otimizado(f"Erro ao salvar configurações de acessibilidade: {str(e)}", 'error', forcar=True)
        return jsonify({'error': str(e)}), 500

@app.route('/get_accessibility_settings')
def get_accessibility_settings():
    """Recupera as configurações de acessibilidade da sessão do usuário"""
    try:
        settings = session.get('accessibility_settings', {
            'fontSize': 0,
            'isLightMode': False
        })
        return jsonify(settings)
    except Exception as e:
        log_otimizado(f"Erro ao recuperar configurações de acessibilidade: {str(e)}", 'error', forcar=True)
        return jsonify({'error': str(e)}), 500

def salvar_emails_sessao(emails, categoria='INBOX'):
    """Salva emails na sessão do usuário, isolado por categoria."""
    if 'emails' not in session:
        session['emails'] = {}
    session['emails'][categoria] = emails
    session.modified = True


def obter_emails_sessao(categoria='INBOX'):
    """Obtém emails da sessão do usuário para a categoria."""
    return session.get('emails', {}).get(categoria, [])

# RODAR APP
if __name__ == "__main__":
    try:
        port = int(os.environ.get('PORT', 5000))
        log_otimizado(f" Iniciando na porta {port}", 'info')
        log_otimizado(f"📊 Módulos disponíveis:")
        log_otimizado(f"  - email_innit: {EMAIL_INNIT_AVAILABLE}")
        log_otimizado(f"  - email_relatorio: {EMAIL_RELATORIO_AVAILABLE}")
        log_otimizado(f"  - site_relatorio: {SITE_RELATORIO_AVAILABLE}")
        log_otimizado(f"  - site_natureza: {SITE_ANALISE_SITE_AVAILABLE}")
        
        app.run(debug=False, port=port, host='0.0.0.0')
    except Exception as e:
        log_otimizado(f"💥 ERRO CRÍTICO: {str(e)}", 'error', forcar=True)
        traceback.print_exc()
