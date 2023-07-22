from rest_framework import viewsets, mixins
from rest_framework.permissions import AllowAny
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import serializers

from src.users.models import User
from src.users.permissions import IsUserOrReadOnly
from src.users.serializers import CreateUserSerializer, UserSerializer, UpdateUserSerializer, RequestPasswordResetSerializer, PasswordResetSerializer, LoginSerializer

import os
import requests
from django.contrib.auth import login, logout, authenticate
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from src.common.helpers import build_absolute_uri


class UserViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    Creates, Updates and Retrieves - User Accounts
    """

    queryset = User.objects.all()
    serializers = {'default': UserSerializer, 
                   'create': CreateUserSerializer,
                   'update':UpdateUserSerializer,
                   'request_password_reset': RequestPasswordResetSerializer,
                   'password_reset' : PasswordResetSerializer,
                   'login_view':LoginSerializer,
                   }
    permissions = {'default': (IsUserOrReadOnly,), 'create': (AllowAny,)}
    parser_classes = (MultiPartParser, FormParser)

    def get_serializer_class(self):
        return self.serializers.get(self.action, self.serializers['default'])

    def get_permissions(self):
        self.permission_classes = self.permissions.get(self.action, self.permissions['default'])
        return super().get_permissions()
    

    @action(detail=False, methods=['get'], url_path='me', url_name='me')
    def get_user_data(self, instance):
        try:
            return Response(UserSerializer(self.request.user, context={'request': self.request}).data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': 'Wrong auth token' + e}, status=status.HTTP_400_BAD_REQUEST)
        
    
    
    def send_email_verification(self, id, email):
        """Storing email using current user instance and sending a 
            verification link to that email address. Works only when the user is in logged in. 
        
        Args:
            id (_type_): string
            email (_type_): string

        Returns:
            _type_: _description_
        """
        user = User.objects.get(id = id)
        VERIFICATION_URL = build_absolute_uri(f"/api/v1/users/verify-email/?token={user.id}")
        message = "click following link to verify your email address: " + VERIFICATION_URL
        print(message)
        send_mail(
                "Email Verification",  #Email subject
                f"Hi, {user.username}" +"\n\t"+ message, #body
                  "noreply@gmail.com",  #sent from
                  [email],  #sent to
                  fail_silently=False)
        user.save()
        return f"{message}"
      
        
    
    
    def update(self, request, *args, **kwargs):
        """
        Updates editable user fields. Sends OTP and verification link for phone number
        and email update. 
        """
        
        data = self.request.data
        print(data)
        user = User.objects.get(id=self.request.user.id)

        report = "Fields saved."
  
        if "username" in data.keys():
            if User.objects.filter(username = data['username']):
                raise serializers.ValidationError({'username':'This user already exists'})
            else:
                user.save()
            
            
        if "email" in data.keys():
            if User.objects.filter(email = data['email']):
                raise serializers.ValidationError({'email':'A user with this email already exists'})
            else:
                report+=f" {self.send_email_verification(user.id, data['email'])}."
                # user.is_emailverified = False
                user.save()
            
        if "phone_number" in data.keys():
            if User.objects.filter(phone_number = data['phone_number']):
                raise serializers.ValidationError({'phone_number':'A user with this phone_number already exists'})
            
            else:
                user.save()
            
        
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(f"{report}", status=status.HTTP_200_OK)
    
    
    
    
    def send_password_reset_email(self, id, email):
        """Checks if email givin is same as user's email and sends an email with a token 
        
        Args:
            id (_type_): string
            email (_type_): string

        Returns:
            _type_: string
        """
        user = User.objects.get(id = id)
        PASSWORD_RESET_URL = build_absolute_uri(f"/api/v1/users/{user.id}/password-reset")
        message = "click following link to verify your email address: " + PASSWORD_RESET_URL
        print(message)
        send_mail(
                "Email Verification",  #Email subject
                f"Hi, {user.username}" +"\n\t"+ message, #body
                  "noreply@gmail.com",  #sent from
                  [email],  #sent to
                  fail_silently=False)
        
        user.is_emailverified=True #storing status as false since email hasn not being verified
        user.save()
        return f"{message}"
    
    
    
    
    
    @action(detail=False, methods=['get'], url_path='verify-email', url_name='verify-email')
    def verify_email(self, serializer):
        """
        Checks the that the user ID/token in the link matches the one assigned to that user. 
        """
        try:
            user = User.objects.get(id = self.request.query_params.get('token')) #verifyint that user id in session is the same with posted id 
            user.is_emailverified = True #Setting to true on successful verification
            user.save()
            return Response("Your mail has been verified", status=status.HTTP_200_OK)
        
        except:
            return Response("Your email verification was unsuccessful", status=status.HTTP_400_BAD_REQUEST) 
        
    
    
    
    
    @action(detail=False, methods=['post'], url_path='(?P<id>[0-9a-f\-]{32,})/password-reset', url_name='password-reset')
    def password_reset(self, serializer, id):
        """
        Confirms user and resets password
        """
        
        user = User.objects.get(id = id)
        user.set_password(self.request.data['new_password'])
        user.save()
        return Response("Success", status=status.HTTP_200_OK)  
    
    
    
    
    
    @action(detail=False, methods=['post'], url_path='request-password-reset', url_name='request-password-request')
    def request_password_reset(self, serializer):
        """
        Sends password reset email to users
        """
        try:
            user = User.objects.get(email = self.request.data['email'])
            if user.is_active:
                if user.is_emailverified and 'email' in self.request.data:
                    if user.email == self.request.data['email']:
                        print("here")
                        report = self.send_password_reset_email(user.id, user.email)
                        return Response(report, status=status.HTTP_200_OK)
                    else:
                        return Response('Unverified email address', status=status.HTTP_401_UNAUTHORIZED)
                        
                else:
                    return Response("Invalid Credentials", status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response("Sorry, this account has been deactivated", status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response("Invalid Credentials" , status=status.HTTP_400_BAD_REQUEST)
        
    
    
    @action(detail=False, methods = ['post'], url_path='login', url_name='login')
    def login_view(self, request):
        """
        User Login via Username and Password
        """
        username = request.data['username']
        password = request.data['password']
        
        user = authenticate(request, username=username,password=password)
        print(user)
        
        if user is not None:
            login(request, user)
            return Response('Logged in', status=status.HTTP_200_OK)
        
        else:
            return Response(f"Invalid Credentials", status=status.HTTP_401_UNAUTHORIZED)
        
    
    
    
    @action(detail=False, methods = ['get'], url_path='logout', url_name='logout')
    def logout_view(self, request):
        """
        User Logout
        """
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)
        