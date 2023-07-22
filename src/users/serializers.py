from rest_framework import serializers

from src.users.models import User
from src.common.serializers import ThumbnailerJSONSerializer


class UserSerializer(serializers.ModelSerializer):
    profile_picture = ThumbnailerJSONSerializer(required=False, allow_null=True, alias_target='src.users')

    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'first_name',
            'last_name',
            'other_name',
            'email',
            'phone_number',
            'gender',
            'date_of_birth',
            'house_address',
            'city',
            'state',
            'bvn',
            'is_bvnverified',
            'is_emailverified',
            'profile_picture',
        )
        read_only_fields = ('username', 'is_emailverified',)


class CreateUserSerializer(serializers.ModelSerializer):
    profile_picture = ThumbnailerJSONSerializer(required=False, allow_null=True, alias_target='src.users')
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, user):
        return user.get_tokens()

    def create(self, validated_data):
        # call create_user on user object. Without this
        # the password will be stored in plain text.
        user = User.objects.create_user(**validated_data)
        return user

    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'password',
            'first_name',
            'last_name',
            'email',
            'tokens',
            'profile_picture',
        )
        read_only_fields = ('tokens',)
        extra_kwargs = {'password': {'write_only': True}}


class UpdateUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=50, required=False)
    
    class Meta:
        model = User
        fields = (
                'username',
                'first_name',
                'last_name',
                'other_name',
                'date_of_birth',
                'house_address',
                'state',
                'profile_picture',
                'email',
                'phone_number',
                'bvn',
            )
            
        
        
        
class ValidUsernameSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=30, required=False)
    class Meta:
        model = User
        fields = ('username',)
        
class RequestPasswordResetSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ( 'email',)
        
class PasswordResetSerializer(serializers.ModelSerializer):
    new_password = serializers.CharField(max_length=225, required=True)
    
    class Meta:
        model = User
        fields = ('new_password',)

class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255, min_length=4)
    password = serializers.CharField(max_length=225, min_length=4, write_only=True)
    class Meta:
        model = User
        fields = ('username','password',)