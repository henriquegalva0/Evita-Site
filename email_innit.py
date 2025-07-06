import base64
import tqdm
import time
from datetime import datetime, timezone
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from email.utils import parsedate_to_datetime
import re
import os
import json
import secrets
from urllib.parse import urlparse
from google.auth.transport.requests import Request
import pytesseract
from PIL import Image
import io
from config import OAUTH_CALLBACK_URL, ENV, OAUTHLIB_INSECURE_TRANSPORT
import os
from bs4 import BeautifulSoup

if OAUTHLIB_INSECURE_TRANSPORT:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Updated scopes - including what Google automatically adds
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]

# Constantes para categorias de emails
EMAIL_CATEGORIES = {
    'INBOX': 'Caixa de Entrada',
    'SPAM': 'Spam',
    'IMPORTANT': 'Importantes',
    'STARRED': 'Com Estrela',
    'ALL': 'Todos os Emails'
}

def extrair_email(texto):
    """Extract email from text like 'Name <email@domain.com>'"""
    if not texto:
        return None
    padrao = r'<([^<>]+)>'
    resultado = re.search(padrao, texto)
    if resultado:
        return resultado.group(1)
    # If no angle brackets, assume the whole text is the email
    return texto.strip()

def tratar_data(data_bruta):
    """Convert various date formats to DD-MM-YY"""
    if not data_bruta:
        return ''
    
    formatos_possiveis = [
        '%d/%m/%Y',  # 20/05/2024
        '%d-%m-%Y',  # 20-05-2024
        '%d/%m/%y',  # 20/05/24
        '%d-%m-%y',  # 20-05-24
        '%Y-%m-%d',  # 2024-05-20 (formato ISO)
    ]

    for formato in formatos_possiveis:
        try:
            data = datetime.strptime(data_bruta.strip(), formato)
            return data.strftime('%d-%m-%y')
        except ValueError:
            continue

    return ''

def get_redirect_uri():
    """Determina o redirect URI baseado no ambiente"""
    return OAUTH_CALLBACK_URL

def iniciar_flow_oauth(custom_state=None):
    """
    Initialize OAuth flow and return authorization URL
    Improved version with better error handling and flexible redirect URI
    """
    try:
        print(f"=== INICIANDO OAUTH ===")
        print(f"Escopos solicitados: {SCOPES}")

        # Determina redirect URI dinamicamente
        redirect_uri = get_redirect_uri()
        print(f"Redirect URI determinado: {redirect_uri}")
        
        # Check if credentials file exists
        credentials_path = 'data/keys/credentials.json'
        if not os.path.exists(credentials_path):
            return {
                'success': False,
                'error': f'Arquivo de credenciais não encontrado: {credentials_path}'
            }

        # Create flow
        flow = Flow.from_client_secrets_file(
            credentials_path,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )

        # Generate authorization URL
        if custom_state:
            authorization_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent',
                state=custom_state
            )
        else:
            authorization_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'
            )

        print(f"State gerado: {state}")
        print(f"Redirect URI: {redirect_uri}")
        print(f"URL de autorização gerada com sucesso")

        return {
            'success': True,
            'authorization_url': authorization_url,
            'state': state,
            'scopes': SCOPES,
            'redirect_uri': redirect_uri
        }

    except FileNotFoundError as e:
        error_msg = f'Arquivo credentials.json não encontrado: {str(e)}'
        print(f"ERRO: {error_msg}")
        return {'success': False, 'error': error_msg}
    except Exception as e:
        error_msg = f'Erro ao iniciar OAuth: {str(e)}'
        print(f"ERRO: {error_msg}")
        return {'success': False, 'error': error_msg}

def finalizar_oauth(authorization_response, expected_state=None, original_scopes=None):
    """
    Complete OAuth flow with authorization code
    Improved error handling and flexible scope validation
    """
    try:
        print(f"=== FINALIZANDO OAUTH ===")
        print(f"Authorization response recebida")
        print(f"Expected state: {expected_state}")

        # Use original scopes if provided, otherwise use default
        scopes_to_use = original_scopes if original_scopes else SCOPES
        redirect_uri = get_redirect_uri()
        print(f"Usando redirect URI: {redirect_uri}")

        # Create flow
        flow = Flow.from_client_secrets_file(
            'data/keys/credentials.json',
            scopes=scopes_to_use,
            redirect_uri=redirect_uri
        )

        # Exchange code for credentials
        print("Trocando código por credenciais...")
        flow.fetch_token(authorization_response=authorization_response)
        
        # Get the actual granted scopes
        granted_scopes = flow.credentials.scopes or []
        print(f"Escopos solicitados: {scopes_to_use}")
        print(f"Escopos concedidos: {granted_scopes}")

        # Validate that we have the minimum required scopes (mais flexível)
        required_scopes = [
            'https://www.googleapis.com/auth/gmail.readonly'
        ]
        
        has_required_scopes = True
        missing_scopes = []
        
        for required_scope in required_scopes:
            scope_found = False
            for granted_scope in granted_scopes:
                if required_scope in granted_scope or granted_scope in required_scope:
                    scope_found = True
                    break
            
            if not scope_found:
                missing_scopes.append(required_scope)
                has_required_scopes = False
        
        if not has_required_scopes:
            error_msg = f"Escopos obrigatórios não concedidos: {missing_scopes}"
            print(f"ERRO: {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'error_type': 'MissingScopes',
                'granted_scopes': granted_scopes,
                'required_scopes': required_scopes
            }

        # Create Gmail service
        print("Criando serviço Gmail...")
        service = build('gmail', 'v1', credentials=flow.credentials)
        
        # Test the service with a simple call
        try:
            profile = service.users().getProfile(userId='me').execute()
            email_address = profile.get('emailAddress', 'N/A')
            print(f"Serviço Gmail criado com sucesso para: {email_address}")
        except Exception as e:
            print(f"Aviso: Não foi possível testar o serviço Gmail: {str(e)}")
            # Não falha aqui, apenas avisa

        # Prepare credentials data for session storage
        credentials_data = {
            'token': flow.credentials.token,
            'refresh_token': flow.credentials.refresh_token,
            'token_uri': flow.credentials.token_uri,
            'client_id': flow.credentials.client_id,
            'client_secret': flow.credentials.client_secret,
            'scopes': granted_scopes
        }

        return {
            'success': True,
            'service': service,
            'credentials': flow.credentials,
            'credentials_data': credentials_data,
            'scopes_granted': granted_scopes,
            'email_address': profile.get('emailAddress', 'N/A') if 'profile' in locals() else 'N/A'
        }

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        error_msg = f'Erro na autenticação OAuth: {str(e)}'
        print(f"ERRO: {error_msg}")
        print(f"Stack trace: {error_details}")
        
        return {
            'success': False,
            'error': error_msg,
            'error_type': type(e).__name__,
            'error_details': error_details,
            'authorization_response': authorization_response[:100] + '...' if len(authorization_response) > 100 else authorization_response
        }

def criar_servico_gmail(credentials_data):
    """
    Create Gmail service from stored credentials data
    Improved error handling and credential refresh
    """
    try:
        if not credentials_data:
            print("Nenhum dado de credencial fornecido")
            return None

        print("Recriando serviço Gmail a partir de credenciais armazenadas...")
        
        credentials = Credentials(
            token=credentials_data.get('token'),
            refresh_token=credentials_data.get('refresh_token'),
            token_uri=credentials_data.get('token_uri'),
            client_id=credentials_data.get('client_id'),
            client_secret=credentials_data.get('client_secret'),
            scopes=credentials_data.get('scopes', SCOPES)
        )

        # Check if credentials need refresh
        if credentials.expired and credentials.refresh_token:
            print("Credenciais expiradas, tentando renovar...")
            try:
                credentials.refresh(Request())
                print("Credenciais renovadas com sucesso")
            except Exception as refresh_error:
                print(f"Erro ao renovar credenciais: {str(refresh_error)}")
                return None

        service = build('gmail', 'v1', credentials=credentials)
        
        # Test the service
        try:
            profile = service.users().getProfile(userId='me').execute()
            email_address = profile.get('emailAddress', 'N/A')
            print(f"Serviço Gmail recriado com sucesso para: {email_address}")
        except Exception as test_error:
            print(f"Aviso: Não foi possível testar o serviço recriado: {str(test_error)}")
            # Retorna o serviço mesmo assim, pode funcionar
        
        return service

    except Exception as e:
        print(f"Erro ao recriar serviço Gmail: {str(e)}")
        import traceback
        print(f"Stack trace: {traceback.format_exc()}")
        return None

# NOVAS FUNÇÕES PARA EXTRAÇÃO COMPLETA DE CONTEÚDO

def extrair_links_texto(texto):
    """Extrai links de texto simples"""
    if not texto:
        return []
    
    # Padrão para URLs em texto
    padrao_url = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return re.findall(padrao_url, texto)

def extrair_links_html(html):
    """Extrai links de conteúdo HTML"""
    if not html:
        return []
    
    # Padrão para links em HTML (href)
    padrao_href = r'href=[\'"]([^\'" >]+)[\'"]'
    return re.findall(padrao_href, html)

def analisar_links(links):
    """Analisa e categoriza links encontrados"""
    links_analisados = []
    
    for link in links:
        try:
            parsed = urlparse(link)
            link_info = {
                'url': link,
                'dominio': parsed.netloc,
                'protocolo': parsed.scheme,
                'caminho': parsed.path,
                'parametros': parsed.query
            }
            links_analisados.append(link_info)
        except Exception as e:
            print(f"Erro ao analisar link {link}: {str(e)}")
    
    return links_analisados

def extrair_texto_imagem(imagem_bytes):
    """Extrai texto de uma imagem usando OCR (Tesseract)"""
    try:
        imagem = Image.open(io.BytesIO(imagem_bytes))
        texto = pytesseract.image_to_string(imagem, lang='por')
        return texto.strip()
    except Exception as e:
        print(f"Erro ao extrair texto da imagem: {e}")
        return ''

def extrair_imagens_base64_html(html):
    """Extrai imagens base64 do HTML do email"""
    imagens = []
    if not html:
        return imagens
    # Regex para encontrar imagens base64
    padrao = r'<img[^>]+src=["\"](data:image/[^;]+;base64,([^"\"]+))["\"]'
    for match in re.finditer(padrao, html, re.IGNORECASE):
        base64_full = match.group(1)
        base64_data = match.group(2)
        imagens.append((base64_full, base64_data))
    return imagens

def extrair_conteudo_email(msg_detail, service=None, remetente=None, assunto=None, data=None):
    """
    Extrai conteúdo completo de um email: texto, HTML, links e anexos, incluindo fallback HTML->texto e estruturação para IA.
    """
    resultado = {
        'texto_simples': '',
        'html': '',
        'links': [],
        'anexos': [],
        'imagens': [],
        'texto_imagens': '',
        'texto_ia': ''  # Novo campo: texto estruturado para IA
    }
    if not msg_detail or 'payload' not in msg_detail:
        print('[LOG EMAIL] Email sem payload.')
        return resultado
    payload = msg_detail['payload']
    print('[LOG EMAIL] Iniciando extração do email.')
    def processar_parte(part):
        mime_type = part.get('mimeType', '')
        if mime_type == 'text/plain':
            body_data = part.get('body', {}).get('data', '')
            if body_data:
                texto = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                resultado['texto_simples'] += texto
                print(f'[LOG EMAIL] Texto simples extraído: {texto[:100]}...')
                links_texto = extrair_links_texto(texto)
                resultado['links'].extend(links_texto)
        elif mime_type == 'text/html':
            body_data = part.get('body', {}).get('data', '')
            if body_data:
                html = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                resultado['html'] += html
                print(f'[LOG EMAIL] HTML extraído (primeiros 200 chars): {html[:200]}...')
                links_html = extrair_links_html(html)
                resultado['links'].extend(links_html)
                imagens_base64 = extrair_imagens_base64_html(html)
                print(f'[LOG EMAIL] {len(imagens_base64)} imagem(ns) base64 encontrada(s) no HTML.')
                for base64_full, base64_data in imagens_base64:
                    try:
                        import base64 as b64
                        imagem_bytes = b64.b64decode(base64_data)
                        texto_ocr = extrair_texto_imagem(imagem_bytes)
                        if texto_ocr:
                            print(f'[LOG EMAIL] Texto extraído via OCR de imagem base64: {texto_ocr[:100]}...')
                            resultado['texto_imagens'] += '\n' + texto_ocr
                    except Exception as e:
                        print(f"Erro ao processar OCR de imagem base64: {e}")
        elif part.get('filename'):
            anexo = {
                'nome': part['filename'],
                'mime_type': mime_type,
                'tamanho': part.get('body', {}).get('size', 0),
                'attachment_id': part.get('body', {}).get('attachmentId'),
                'message_id': msg_detail.get('id')
            }
            if mime_type.startswith('image/'):
                resultado['imagens'].append(anexo)
                print(f'[LOG EMAIL] Imagem anexa encontrada: {anexo["nome"]} ({mime_type})')
                if service and anexo['attachment_id']:
                    try:
                        imagem_bytes = baixar_anexo(service, anexo['message_id'], anexo['attachment_id'])
                        if imagem_bytes:
                            texto_ocr = extrair_texto_imagem(imagem_bytes)
                            if texto_ocr:
                                print(f'[LOG EMAIL] Texto extraído via OCR de anexo: {texto_ocr[:100]}...')
                                resultado['texto_imagens'] += '\n' + texto_ocr
                    except Exception as e:
                        print(f"Erro ao processar OCR da imagem: {e}")
            else:
                resultado['anexos'].append(anexo)
        if 'parts' in part:
            for sub_part in part['parts']:
                processar_parte(sub_part)
    if 'parts' in payload:
        for part in payload['parts']:
            processar_parte(part)
    else:
        processar_parte(payload)
    # Deduplicar links
    resultado['links'] = list(set(resultado['links']))
    resultado['links_analisados'] = analisar_links(resultado['links'])
    # Fallback: se não houver texto_simples, extrair do HTML
    if not resultado['texto_simples'] and resultado['html']:
        try:
            soup = BeautifulSoup(resultado['html'], 'html.parser')
            texto_html = soup.get_text(separator='\n', strip=True)
            resultado['texto_simples'] = texto_html
            print(f'[LOG EMAIL] Fallback: texto extraído do HTML.')
        except Exception as e:
            print(f'[LOG EMAIL] Erro ao converter HTML para texto: {e}')
    # Montar texto estruturado para IA
    texto_ia = ''
    if remetente:
        texto_ia += f'Remetente: {remetente}\n'
    if assunto:
        texto_ia += f'Assunto: {assunto}\n'
    if data:
        texto_ia += f'Data: {data}\n'
    if resultado['links']:
        texto_ia += '\n[Links encontrados no email]\n' + '\n'.join(resultado['links']) + '\n'
    if resultado['anexos']:
        texto_ia += '\n[Anexos]\n'
        for anexo in resultado['anexos']:
            texto_ia += f"{anexo['nome']} (tipo: {anexo['mime_type']}, tamanho: {anexo['tamanho']} bytes)\n"
    if resultado['imagens']:
        texto_ia += '\n[Imagens anexas]\n'
        for img in resultado['imagens']:
            texto_ia += f"{img['nome']} (tipo: {img['mime_type']}, tamanho: {img['tamanho']} bytes)\n"
    texto_ia += '\n[Corpo do email]\n' + (resultado['texto_simples'] or '[sem corpo]')
    resultado['texto_ia'] = texto_ia
    print(f'[LOG EMAIL] Texto estruturado para IA montado (primeiros 300 chars): {texto_ia[:300]}...')
    print(f'[LOG EMAIL] Texto final extraído: {resultado["texto_simples"][:200]}...')
    print(f'[LOG EMAIL] Texto extraído de imagens (OCR): {resultado["texto_imagens"][:200]}...')
    print(f'[LOG EMAIL] Total de imagens anexas: {len(resultado["imagens"])}')
    print(f'[LOG EMAIL] Total de anexos: {len(resultado["anexos"])}')
    print(f'[LOG EMAIL] Total de links: {len(resultado["links"])}')
    return resultado

def baixar_anexo(service, message_id, attachment_id):
    """
    Baixa um anexo específico de um email
    Retorna os dados binários do anexo
    """
    if not service or not message_id or not attachment_id:
        return None
    
    try:
        attachment = service.users().messages().attachments().get(
            userId='me',
            messageId=message_id,
            id=attachment_id
        ).execute()
        
        if 'data' in attachment:
            file_data = base64.urlsafe_b64decode(attachment['data'])
            return file_data
        return None
    except Exception as e:
        print(f"Erro ao baixar anexo: {str(e)}")
        return None

def buscar_email_inteligente(service, msg_id, formato='metadata'):
    """
    Busca email de forma inteligente - metadados primeiro, conteúdo completo quando necessário
    """
    try:
        if formato == 'metadata':
            # Busca apenas metadados (muito mais rápido)
            return service.users().messages().get(
                userId='me', id=msg_id, format='metadata'
            ).execute()
        else:
            # Busca conteúdo completo quando necessário
            return service.users().messages().get(
                userId='me', id=msg_id, format='full'
            ).execute()
    except Exception as e:
        print(f"Erro ao buscar email {msg_id}: {str(e)}")
        return None

def buscar_emails_por_categoria(service, categoria='INBOX', quantidade_emails=25):
    """
    Busca emails de uma categoria específica (INBOX, SPAM, IMPORTANT, STARRED) - OTIMIZADO
    """
    try:
        if not service:
            print("Serviço Gmail não disponível")
            return []

        # Validar quantidade
        if not isinstance(quantidade_emails, int) or quantidade_emails < 1:
            quantidade_emails = 25
        elif quantidade_emails > 500:
            quantidade_emails = 500

        print(f"Buscando {quantidade_emails} emails da categoria: {categoria}")
        
        # Definir parâmetros de busca com base na categoria
        params = {
            'userId': 'me',
            'maxResults': quantidade_emails
        }
        
        # Configurar labelIds com base na categoria
        if categoria == 'ALL':
            # Não especificar labelIds para buscar todos os emails
            pass
        else:
            params['labelIds'] = [categoria]
        
        # Buscar mensagens
        results = service.users().messages().list(**params).execute()
        
        messages = results.get('messages', [])
        if not messages:
            print(f"Nenhum email encontrado na categoria {categoria}")
            return []
        
        emails = []
        print(f"Processando {len(messages)} emails da categoria {categoria}...")
        
        # OTIMIZAÇÃO: Processar metadados primeiro (muito mais rápido)
        for msg in tqdm.tqdm(messages, desc=f'Carregando metadados ({categoria})', unit='email'):
            try:
                # Buscar apenas metadados primeiro (muito mais rápido)
                msg_detail = buscar_email_inteligente(service, msg['id'], 'metadata')
                if not msg_detail:
                    continue
                
                # Extrair cabeçalhos dos metadados
                headers = msg_detail['payload']['headers']
                assunto = remetente = data = ''
                
                for header in headers:
                    if header['name'] == 'Subject':
                        assunto = header['value'] or "(sem assunto)"
                    elif header['name'] == 'From':
                        remetente = header['value'] or "(remetente desconhecido)"
                    elif header['name'] == 'Date':
                        data = header['value'] or "(sem data)"
                
                # Obter labels para identificar categorias
                labels = msg_detail.get('labelIds', [])
                
                # Criar objeto de email básico (sem conteúdo completo)
                email_basico = {
                    'id': msg['id'],
                    'remetente': remetente,
                    'remetente_email': extrair_email(remetente),
                    'assunto': assunto,
                    'data': data,
                    'data_formatada': tratar_data(data) if data else '',
                    'corpo': '',  # Será carregado sob demanda
                    'html': '',
                    'texto_simples': '',
                    'links': [],
                    'links_analisados': [],
                    'anexos': [],
                    'imagens': [],
                    'total_anexos': 0,
                    'total_links': 0,
                    'labels': labels,
                    'categoria': categoria,
                    'categorias': [
                        label for label in ['INBOX', 'SPAM', 'IMPORTANT', 'STARRED'] 
                        if label in labels
                    ],
                    'is_spam': 'SPAM' in labels,
                    'is_important': 'IMPORTANT' in labels,
                    'is_starred': 'STARRED' in labels,
                    'is_unread': 'UNREAD' in labels,
                    'conteudo_carregado': False  # Flag para indicar se conteúdo foi carregado
                }
                
                emails.append(email_basico)
                
            except Exception as e:
                print(f"Erro ao processar email {msg.get('id', 'unknown')}: {str(e)}")
                continue
        
        print(f"Carregamento otimizado concluído: {len(emails)} emails da categoria {categoria} processados")
        return emails
        
    except Exception as e:
        print(f"Erro ao buscar emails da categoria {categoria}: {str(e)}")
        return []

def carregar_conteudo_email_completo(service, email_basico):
    """
    Carrega conteúdo completo de um email específico (sob demanda)
    """
    try:
        if email_basico.get('conteudo_carregado', False):
            return email_basico  # Já foi carregado
        
        # Buscar conteúdo completo apenas quando necessário
        msg_detail = buscar_email_inteligente(service, email_basico['id'], 'full')
        if not msg_detail:
            return email_basico
        
        # Extrair conteúdo completo
        conteudo = extrair_conteudo_email(
            msg_detail,
            service,
            remetente=email_basico.get('remetente'),
            assunto=email_basico.get('assunto'),
            data=email_basico.get('data')
        )
        # Atualizar email com conteúdo completo
        corpo_completo = conteudo['texto_simples']
        if conteudo.get('texto_imagens'):
            corpo_completo += '\n[Texto extraído de imagem:]\n' + conteudo['texto_imagens']
        email_basico.update({
            'corpo': corpo_completo,
            'html': conteudo['html'],
            'texto_simples': corpo_completo,
            'links': conteudo['links'],
            'links_analisados': conteudo['links_analisados'],
            'anexos': conteudo['anexos'],
            'imagens': conteudo['imagens'],
            'total_anexos': len(conteudo['anexos']) + len(conteudo['imagens']),
            'total_links': len(conteudo['links']),
            'conteudo_carregado': True,
            'texto_ia': conteudo['texto_ia']
        })
        
        print(f"✓ Conteúdo completo carregado para email {email_basico['id']}")
        return email_basico
        
    except Exception as e:
        print(f"Erro ao carregar conteúdo completo do email {email_basico.get('id', 'unknown')}: {str(e)}")
        return email_basico

def buscar_emails(service, quantidade_emails=25):
    """
    Fetch emails from Gmail with improved content extraction
    Mantida para compatibilidade com código existente
    """
    return buscar_emails_por_categoria(service, 'INBOX', quantidade_emails)

def remetentes(emails, autor_alvo):
    """Filter emails by sender with improved error handling"""
    try:
        if not emails or not autor_alvo:
            return {'Resultado': 'Parâmetros inválidos para filtro de remetente'}

        escolha = autor_alvo.strip().lower()
        
        # Get unique senders
        remetentes_unicos = set()
        for email in emails:
            if isinstance(email, dict) and email.get('remetente'):
                email_extraido = extrair_email(email['remetente'])
                if email_extraido:
                    remetentes_unicos.add(email_extraido.lower())

        remetentes_unicos = list(remetentes_unicos)
        print(f"Remetentes únicos encontrados: {len(remetentes_unicos)}")

        # Check if target sender exists
        if escolha not in remetentes_unicos:
            return {'Resultado': f'Nenhum email encontrado do remetente: {autor_alvo}'}

        # Filter emails
        emails_filtrados = []
        for email in emails:
            if isinstance(email, dict) and email.get('remetente'):
                email_extraido = extrair_email(email['remetente'])
                if email_extraido and email_extraido.lower() == escolha:
                    emails_filtrados.append(email)

        print(f"Emails filtrados por remetente: {len(emails_filtrados)}")
        return emails_filtrados

    except Exception as e:
        print(f"Erro ao filtrar por remetente: {str(e)}")
        return {'Resultado': f'Erro ao filtrar emails: {str(e)}'}

def data(emails, data_definida_naotratada):
    """Filter emails by date with improved error handling"""
    try:
        if not emails or not data_definida_naotratada:
            return {'Resultado': 'Parâmetros inválidos para filtro de data'}

        data_definida = tratar_data(data_definida_naotratada)
        if not data_definida:
            return {'Resultado': 'Formato de data inválido. Use DD/MM/YYYY ou DD-MM-YYYY'}

        print(f"Filtrando emails pela data: {data_definida}")

        # Parse target date
        data_base = datetime.strptime(data_definida, '%d-%m-%y')
        data_inicio = data_base.replace(hour=0, minute=0, second=0, microsecond=0)
        data_final = data_base.replace(hour=23, minute=59, second=59, microsecond=999999)

        emails_filtrados = []
        for email in emails:
            try:
                if not email.get('data'):
                    continue
                    
                data_email = parsedate_to_datetime(email['data'])
                if data_email is None:
                    continue
                    
                # Convert to UTC for comparison
                data_email = data_email.astimezone(timezone.utc).replace(tzinfo=None)
                
                if data_inicio <= data_email <= data_final:
                    emails_filtrados.append(email)
                    
            except Exception as e:
                print(f"Erro ao processar data do email: {str(e)}")
                continue

        if not emails_filtrados:
            return {'Resultado': f'Nenhum email encontrado na data: {data_definida_naotratada}'}

        print(f"Emails filtrados por data: {len(emails_filtrados)}")
        return emails_filtrados

    except Exception as e:
        print(f"Erro ao filtrar por data: {str(e)}")
        return {'Resultado': f'Erro ao filtrar emails: {str(e)}'}

def obter_categorias_disponiveis(service):
    """
    Obtém as categorias disponíveis e a contagem de emails em cada uma
    """
    try:
        if not service:
            return {}
        
        # Obter todas as labels disponíveis
        labels_response = service.users().labels().list(userId='me').execute()
        labels = labels_response.get('labels', [])
        
        # Filtrar apenas as categorias que nos interessam
        categorias = {}
        for label in labels:
            label_id = label.get('id')
            if label_id in ['INBOX', 'SPAM', 'IMPORTANT', 'STARRED']:
                # Obter contagem de emails nesta categoria
                label_info = service.users().labels().get(userId='me', id=label_id).execute()
                count = label_info.get('messagesTotal', 0)
                
                # Adicionar ao dicionário de categorias
                categorias[label_id] = {
                    'nome': EMAIL_CATEGORIES.get(label_id, label.get('name')),
                    'count': count
                }
        
        # Adicionar categoria "Todos"
        profile = service.users().getProfile(userId='me').execute()
        total_emails = profile.get('messagesTotal', 0)
        categorias['ALL'] = {
            'nome': EMAIL_CATEGORIES.get('ALL'),
            'count': total_emails
        }
        
        return categorias
        
    except Exception as e:
        print(f"Erro ao obter categorias: {str(e)}")
        return {}
