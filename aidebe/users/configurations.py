RESET_PASSWORD_URL: str = "#/reset-password"

ALLOWED_RANDOM_CHARS: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

URL_MESSAGE_SPLITOR: str = "||"

EMAIL_MAIN_TEMPLATE: str = "main.html"
WELCOME_EMAIL_TEMPLATE: str = "welcome.html"
RESET_PASSWORD_EMAIL_TEMPLATE: str = "resetpassword.html"

WELCOME_EMAIL_SUBJECT: str = "Welcome to l3harris"
RESET_PASSWORD_EMAIL_SUBJECT: str = "l3harris: Reset Password"

WELCOME_EMAIL_TIMEOUT: int = 525600
RESET_PASSWORD_EMAIL_TIMEOUT: int = 15
TEAM_INVITE_EMAIL_TIMEOUT: int = 43800



ORGANIZATION_ADMIN: str = "admin"
ORGANIZATION_MANAGER: str = "manager"
ORGANIZATION_SCHEDULER: str = "scheduler"
ORGANIZATION_USER: str = "user"

media_file_path = "/l3harris/media/"


USER_ACTIONS = {
    "GET": {
        "user-info":{
            "description": "Get user info",
        },
        "organization":{
            "description": "Get organizatiom info",
        },
        "organization-list":{
            "description": "Get organizatiom info",
        },
        "document-archive-download":{
            "description": "upload file",
        },
         "first-barplot": {
            "description": "Detailed data figure plot",
        },
        "second-processplot": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-coverage-benefits": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-customer-service": {
            "description": "Detailed data figure plot",
        },

        "data-detailed-figures-phone": {
            "description": "Detailed data figure plot",
        },

        "data-detailed-figures-website": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-information-communication": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-cost": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-provider-choice": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-overall-satisfaction": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-billing-payment": {
            "description": "Detailed data figure plot",
        },

        "data-detailed-figures-nps-loyalty-trust": {
            "description": "Detailed data figure plot",
        },
        "document-archive-get":{
            "description": "upload file",
        },
        "role-data":{
            "description": "role-data-get",
        },
        "predict-liver":{
            "description": "get prediction of liver",
        },
    },
    "POST": {
        "login": {
            "description": "User logged in to l3harris.",
        },
        "refresh": {
            "description": "User logged in to l3harris.",
        },
        "logout": {
            "description": "User logout successfully.",
        },
        "reset-password": {
            "description": "Reset password request sent.",
        },
        "data-process": {
            "description": "Reset password request sent.",
        },
        "data-process-plot": {
            "description": "Reset password request sent.",
        },
        "data-detailed-figures-coverage-benefits": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-customer-service": {
            "description": "Detailed data figure plot",
        },

        "data-detailed-figures-phone": {
            "description": "Detailed data figure plot",
        },

        "data-detailed-figures-website": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-information-communication": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-cost": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-provider-choice": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-overall-satisfaction": {
            "description": "Detailed data figure plot",
        },
        "data-detailed-figures-billing-payment": {
            "description": "Detailed data figure plot",
        },

        "data-detailed-figures-nps-loyalty-trust": {
            "description": "Detailed data figure plot",
        },
        
        "first-barplot": {
            "description": "Executive overview plot",
        },
        "second-processplot": {
            "description": "Executive overview plot",
        },

        "organization":{
            "description": "Create organization",
        },
        "organization-list":{
            "description": "Get organizatiom info",
        },

        "document-archive":{
            "description": "upload file",
        },
        "document-archive-list":{
            "description": "upload file",
        },
        "document-archive-get-file":{
            "description": "upload file",

        },"document-archive-download":{
            "description": "upload file",
        },
    },
    "PUT": {
        "reset-password": {
            "description": "Password reset success.",
        },
        "change-password": {
            "description": "Password changed successfully.",
        },
        "organization":{
            "description": "Update organization ",
        },
        "organization-detail":{
            "description": "Get organizatiom info",
        },
        "profile-update":{
            "description": "Profile update",
        },
    },
    "DELETE": {
        "organization":{
            "description": "Delete organizatiom",
        },
        "organization-delete":{
            "description": "Delete organization",
        },
        "organization-detail":{
            "description": "Get organizatiom info",
        },
    },
}
