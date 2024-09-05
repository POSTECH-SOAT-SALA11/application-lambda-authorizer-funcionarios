import json
import boto3

def lambda_handler(event, context):

    matricula = event['headers'].get('matricula')
    
    if not matricula:
        return generate_policy("user", "Deny", event['methodArn'], "Matrícula não fornecida no header.")

    client = boto3.client('cognito-idp')

    user_pool_id = 'sa-east-1_xEApzyriv'  
    matricula_field = 'preferred_username'

    try:
        matricula = matricula.strip()
        # Verificar se a matrícula começa com 'RM' e é seguida por 6 dígitos
        if not matricula.startswith('RM') or len(matricula) != 8 or not matricula[2:].isdigit():
            return generate_policy("user", "Deny", event['methodArn'], "Matrícula inválida. A matrícula deve começar com 'RM' seguido por 6 dígitos numéricos.")

        filter_expression = f'{matricula_field}="{matricula}"'
        response = client.list_users(
            UserPoolId=user_pool_id,
            Filter=filter_expression
        )
        
        if response['Users']:
            return generate_policy("user", "Allow", event['methodArn'], "Matrícula válida. Funcionário encontrado.")
        else:
            return generate_policy("user", "Deny", event['methodArn'], "Matrícula inválida. Funcionário não encontrado.")

    except client.exceptions.InvalidParameterException as e:
        return generate_policy("user", "Deny", event['methodArn'], f'Erro nos parâmetros fornecidos: {str(e)}')
    except Exception as e:
        return generate_policy("user", "Deny", event['methodArn'], f'Erro ao verificar matrícula: {str(e)}')


def generate_policy(principal_id, effect, resource, message):
    """Helper function to generate an IAM policy"""
    auth_response = {}
    
    auth_response['principalId'] = principal_id

    if effect and resource:
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
        auth_response['policyDocument'] = policy_document
    
    auth_response['context'] = {
        'message': message
    }
    
    return auth_response
