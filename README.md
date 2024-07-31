# API Product ordering service for retail chains
## Description
The application is designed to automate purchases in a retail network via REST API.

### Client
* Makes daily purchases from a catalog that includes items from multiple suppliers.
* Products from different suppliers can be specified in one order.
* User can authorize, register and recover password via API.

### Supplier
* Informs the service about price list updates via API.
* Can enable and disable order acceptance.
* Can receive a list of completed orders (with items from its price list).
## Установка
``bash
    git clone https://github.com/roman3222/API-Partners-and-Manager/tree/master
    ```

2. Create a virtual environment:

    ```bash
    python -m venv venv
    ```

3. activate the virtual environment:

    - For Windows:

        ```bash
        venv\Scripts\activate
        ```

    - For macOS/Linux:

        ```bash
        source env/bin/activate
        ```

4. Install dependencies:

    ````bash
    pip install -r requirements.txt
    ```

5. Apply migrations:

    ````bash
    python manage.py migrate
    ```

6. Create a superuser:

    ````bash
    python manage.py createsuperuser
    ```

7. Start the server:

    ```bash

8. Open the application in a browser at [http://127.0.0.1:8000/](http://127.0.0.1:8000/).

## Additional settings

- Configure the environment variables in the `.env` file:

    ```
    POSTGRES_USER
    POSTGRES_PASSWORD
    POSTGRES_DB
    ```
