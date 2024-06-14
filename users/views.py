from django.contrib.auth import authenticate
from django.http import JsonResponse
from rest_framework import status, generics, response
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import JSONParser
from .models import CustomUser, Post
from .serializers import UserSerializer, PostSerializer, EmailSerializer, ResetPasswordSerializer
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def profile(request, userid):
    try:
        userprofile = CustomUser.objects.get(id=userid)
    except CustomUser.DoesNotExist:
        return JsonResponse({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.user != userprofile:
        return JsonResponse({'error': 'You do not have permission to view this profile'},
                            status=status.HTTP_403_FORBIDDEN)

    if request.method == 'GET':
        serializer = UserSerializer(userprofile)
        return JsonResponse(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        data = JSONParser().parse(request)
        serializer = UserSerializer(userprofile, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=status.HTTP_200_OK)
        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if not username or not password:
            return JsonResponse(
                {'error': 'Username and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        user = authenticate(
            username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return JsonResponse(
                {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token)
                }
            )
        else:
            return JsonResponse(
                {'error': 'Invalid username or password'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = CustomUser.objects.create_user(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password'],
                email=serializer.validated_data['email'],
            )
            refresh = RefreshToken.for_user(user)
            return JsonResponse(
                {'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def post_list(request, pk):
    if request.method == 'GET':
        if pk != request.user.id:
            return JsonResponse({'error': 'You do not have permission to view this post'},
                                status=status.HTTP_403_FORBIDDEN)

        post = Post.objects.get(custom_user=request.user.id)
        if not post:
            return JsonResponse({'error': 'no posts for this user'}, status=status.HTTP_404_NOT_FOUND)
        serializer = PostSerializer(post)
        return JsonResponse(serializer.data, safe=False)


class PasswordReset(generics.GenericAPIView):
    serializer_class = EmailSerializer

    def post(self, request):
        """
        Create token.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data["email"]
        user = CustomUser.objects.filter(email=email).first()
        if user:
            encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = reverse(
                "reset-password",
                kwargs={"encoded_pk": encoded_pk, "token": token},
            )
            reset_link = f"localhost:8000{reset_url}"

            # send the rest_link as mail to the user.

            return response.Response(
                {
                    "message":
                        f"Your password rest link: {reset_link}"
                },
                status=status.HTTP_200_OK,
            )
        else:
            return response.Response(
                {"message": "User doesn't exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ResetPasswordAPI(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def patch(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"kwargs": kwargs}
        )
        serializer.is_valid(raise_exception=True)
        return response.Response(
            {"message": "Password reset complete"},
            status=status.HTTP_200_OK,
        )
