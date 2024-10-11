from django.shortcuts import render

# Create your views here.

from django.shortcuts import render#
from ninja import Router
from users.schemas import UserSignUpSchema, UserLoginSchema, UserProfileSchema
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from ninja.errors import HttpError
from django.shortcuts import get_object_or_404
from rest_framework.authentication import TokenAuthentication
from ninja.security import HttpBearer
from users.models import CustomUser
from django.http import HttpResponseBadRequest


User = get_user_model()
api = Router()

class TokenAuth(HttpBearer):
    def authenticate(self, request, token):
        try:
            user = Token.objects.get(key=token).user
            return user
        except Token.DoesNotExist:
            return None

# Sign-up
#
@api.post("/signup", response=UserProfileSchema)
def signup(request, payload: UserSignUpSchema):
    if CustomUser.objects.filter(email=payload.email).exists():
        return HttpResponseBadRequest("User with this email already exists.")


    user = CustomUser.objects.create_user(
        email=payload.email,
        password=payload.password,
        name=payload.name,
        phone_number=payload.phone_number,
        date_of_birth=payload.date_of_birth,
        address=payload.address,
        gender=payload.gender,
        profile_picture=payload.profile_picture
    )

    return UserProfileSchema.from_orm(user)


@api.post("/login", response={200: str, 401: str})
def login(request, payload: UserLoginSchema):
    user = authenticate(email=payload.email, password=payload.password)
    if not user:
        return 401, "Invalid credentials"
    token, _ = Token.objects.get_or_create(user=user)
    return 200, token.key


@api.get("/profile", response=UserProfileSchema, auth=TokenAuth())
def get_profile(request):
    user = request.auth
    return {
        "name": user.name,
        "email": user.email,
        "phone_number": user.phone_number,
        "date_of_birth": user.date_of_birth,
        "address": user.address,
        "gender": user.gender,
        "profile_picture": user.profile_picture.url if user.profile_picture else None
    }
