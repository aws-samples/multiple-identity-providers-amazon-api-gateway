import json

appointments = { 
                "PI-T123": {
                                    "id": "PI-T123",
                                    "name": "Dave",
                                    "Pet" : "Onyx - Dog. 2y 3m",
                                    "Phone Number": "+1234567",
                                    "Visit History": "Patient History from last visit with primary vet",
                                    "Assigned Veterinarian": "Jane"
                                },
                "PI-T124": {
                                    "id": "PI-T124",
                                    "name": "Joy",
                                    "Pet" : "Jelly - Dog. 6y 2m",
                                    "Phone Number": "+1368728",
                                    "Visit History": "None",
                                    "Assigned Veterinarian": "Jane"
                                },
                "PI-T125": {
                                "id": "PI-T125",
                                "name": "Dave",
                                "Pet" : "Sassy - Cat. 1y",
                                "Phone Number": "+1398777",
                                "Visit History": "Patient History from last visit with primary vet",
                                "Assigned Veterinarian": "Adam"
                            }
                }

def handler(event, context):
    print('Event: ', event)

    try:
        path = event['path']
        http_method = event['httpMethod']

        if '/appointment/' in path and http_method == 'GET':
            appointment_id = path.split('/appointment/')[1]
            if appointments.get(appointment_id): 
                return response_handler({'appointment': appointments[appointment_id]}, 200)
        else:
            return response_handler({}, 404)
        

    except Exception as e:
        print(e)
        return response_handler({'msg': 'Internal Server Error'}, 500)


def response_handler(payload, status_code):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(payload),
        "isBase64Encoded": False
    }
